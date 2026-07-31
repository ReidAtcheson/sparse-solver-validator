use std::iter::FusedIterator;

use blake3::OutputReader;

use crate::{
    BoundaryRule, Dyadic, FinalizedProblem, InstanceSeed, MatrixSpec, ProblemDigest, ProblemError,
    RhsSpec, derive_subseed,
};

const MATRIX_VALUES_LABEL: &str = "matrix/seeded-symmetric-tridiagonal-v1/off-diagonal-values";
const DIA_MATRIX_VALUES_LABEL: &str = "matrix/seeded-symmetric-dia-laplacian-v1/edge-values";
const NONSYMMETRIC_STRUCTURE_LABEL: &str = "matrix/seeded-nonsymmetric-row-sparse-v1/structure";
const NONSYMMETRIC_OFF_DIAGONAL_VALUES_LABEL: &str =
    "matrix/seeded-nonsymmetric-row-sparse-v1/off-diagonal-values";
const NONSYMMETRIC_DIAGONAL_VALUES_LABEL: &str =
    "matrix/seeded-nonsymmetric-row-sparse-v1/diagonal-values";
const PROJECTED_NONSYMMETRIC_PROJECTIONS_LABEL: &str =
    "matrix/seeded-nonsymmetric-row-sparse-v2/projections";
const PROJECTED_NONSYMMETRIC_STRUCTURE_LABEL: &str =
    "matrix/seeded-nonsymmetric-row-sparse-v2/structure";
const PROJECTED_NONSYMMETRIC_OFF_DIAGONAL_VALUES_LABEL: &str =
    "matrix/seeded-nonsymmetric-row-sparse-v2/off-diagonal-values";
const PROJECTED_NONSYMMETRIC_DIAGONAL_VALUES_LABEL: &str =
    "matrix/seeded-nonsymmetric-row-sparse-v2/diagonal-values";
const RHS_VALUES_LABEL: &str = "rhs/seeded-periodic-dyadic-v1/values";
const UNBIASED_STREAM_CONTEXT: &str = "sparse-solve/unbiased-u64-stream/v1";

/// One sorted structural matrix entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MatrixEntry {
    pub column: usize,
    pub value: Dyadic,
}

/// Reviewed bounds and structural facts derived from the registered generator.
///
/// This object is never accepted from JSON. It is recomputed while compiling
/// the finalized problem. Boolean fields are certified guarantees: `false`
/// means the family does not establish the property, not that every possible
/// realization must have its mathematical negation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GeneratorCertificate {
    pub dimension: usize,
    pub structural_nonzeros: usize,
    pub maximum_nonzeros_per_row: u8,
    pub maximum_half_bandwidth: usize,
    /// Family-defined periodic pattern terms used by one public matrix evaluation.
    ///
    /// This is the table period for the legacy tridiagonal family and the sum
    /// of active per-offset patterns for the DIA family. For generated sparse
    /// rows it is the active row-pattern count times the requested row width;
    /// projected rows report every per-slot lookup-table pattern.
    pub matrix_period: usize,
    pub coefficient_fractional_bits: u8,
    pub minimum_off_diagonal_magnitude_mantissa: u64,
    pub maximum_off_diagonal_magnitude_mantissa: u64,
    pub maximum_diagonal_mantissa_bound: u64,
    pub maximum_absolute_row_sum_mantissa_bound: u64,
    pub maximum_absolute_column_sum_mantissa_bound: u64,
    pub strict_diagonal_dominance_margin_mantissa: u64,
    pub rhs_period: usize,
    pub rhs_fractional_bits: u8,
    pub maximum_absolute_rhs_mantissa: u64,
    pub symmetric: bool,
    pub positive_diagonal: bool,
    pub nonpositive_off_diagonal: bool,
    pub strictly_row_diagonally_dominant: bool,
    pub nonsingular_m_matrix: bool,
    pub boundary: BoundaryRule,
}

/// Random-access sparse matrix interface used by both streaming provers and validators.
pub trait SparseMatrix {
    type Row<'a>: ExactSizeIterator<Item = MatrixEntry> + FusedIterator
    where
        Self: 'a;

    fn dimension(&self) -> usize;
    fn structural_nonzeros(&self) -> usize;
    fn row(&self, row: usize) -> Option<Self::Row<'_>>;
}

/// A validated, compiled problem backed only by bounded generator tables.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedProblem {
    problem_digest: ProblemDigest,
    instance_seed: InstanceSeed,
    pub(crate) matrix: CompiledMatrixFamily,
    rhs: GeneratedRhs,
    certificate: GeneratorCertificate,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CompiledMatrixFamily {
    Tridiagonal(PeriodicSymmetricTridiagonal),
    SymmetricDiaLaplacian(PeriodicSymmetricDiaLaplacian),
    NonsymmetricRowSparse(PeriodicNonsymmetricRowSparse),
    ProjectedNonsymmetricRowSparse(ProjectedNonsymmetricRowSparse),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PeriodicSymmetricTridiagonal {
    pub(crate) dimension: usize,
    pub(crate) fractional_bits: u8,
    pub(crate) margin_mantissa: u64,
    /// Negative mantissas for edges `(i, i + 1)`, indexed by `i mod period`.
    pub(crate) off_diagonal_mantissas: Box<[i64]>,
}

/// One positive-offset generated diagonal backed by a range in the flat table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DiaEdgeDescriptor {
    pub(crate) positive_offset: usize,
    pub(crate) table_start: usize,
    pub(crate) table_len: usize,
}

/// Compact shifted graph Laplacian with DIA-generated undirected edges.
///
/// Descriptors and all periodic values are kept in two flat allocations.
/// Symmetry is derived from one canonical positive-offset edge table rather
/// than independently generated rows.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PeriodicSymmetricDiaLaplacian {
    pub(crate) dimension: usize,
    pub(crate) fractional_bits: u8,
    pub(crate) diagonal_shift_mantissa: u64,
    pub(crate) edges: Box<[DiaEdgeDescriptor]>,
    /// Negative matrix off-diagonal mantissas, flattened by edge descriptor.
    pub(crate) off_diagonal_mantissas: Box<[i64]>,
}

/// Periodic, independently generated sparse rows in structure-of-arrays form.
///
/// Each pattern owns a sorted, duplicate-free slice of nonzero signed offsets
/// and a parallel value slice. Diagonal values live in a separate flat table,
/// allowing rows to merge the mandatory diagonal without copying or allocating.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PeriodicNonsymmetricRowSparse {
    pub(crate) dimension: usize,
    pub(crate) fractional_bits: u8,
    pub(crate) off_diagonals_per_pattern: usize,
    pub(crate) signed_offsets: Box<[i32]>,
    pub(crate) off_diagonal_mantissas: Box<[i64]>,
    pub(crate) diagonal_mantissas: Box<[i64]>,
}

/// Sparse rows selected by independent projections of the row-index bits.
///
/// Tables are slot-major. Slot zero is the required diagonal; every remaining
/// slot owns one projection, one signed-offset table, and one coefficient
/// table. Offset slots draw from disjoint increasing buckets, so their realized
/// columns are duplicate-free and ordered for every row. `projection_bits`
/// stores least-significant row-bit positions in pattern-bit order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProjectedNonsymmetricRowSparse {
    pub(crate) dimension: usize,
    pub(crate) fractional_bits: u8,
    pub(crate) pattern_bits: usize,
    pub(crate) row_width: usize,
    pub(crate) projection_bits: Box<[u8]>,
    pub(crate) signed_offsets: Box<[i32]>,
    pub(crate) off_diagonal_mantissas: Box<[i64]>,
    pub(crate) diagonal_mantissas: Box<[i64]>,
}

#[derive(Clone, Copy, Debug)]
struct MatrixSeed(InstanceSeed);

#[derive(Clone, Copy, Debug)]
struct RhsSeed(InstanceSeed);

#[derive(Clone, Copy, Debug)]
struct MatrixFacts {
    dimension: usize,
    structural_nonzeros: usize,
    maximum_nonzeros_per_row: u8,
    maximum_half_bandwidth: usize,
    matrix_period: usize,
    coefficient_fractional_bits: u8,
    minimum_off_diagonal_magnitude_mantissa: u64,
    maximum_off_diagonal_magnitude_mantissa: u64,
    maximum_diagonal_mantissa_bound: u64,
    maximum_absolute_row_sum_mantissa_bound: u64,
    maximum_absolute_column_sum_mantissa_bound: u64,
    strict_diagonal_dominance_margin_mantissa: u64,
    symmetric: bool,
    positive_diagonal: bool,
    nonpositive_off_diagonal: bool,
    strictly_row_diagonally_dominant: bool,
    nonsingular_m_matrix: bool,
    boundary: BoundaryRule,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum GeneratedRhs {
    ManufacturedOnes {
        dimension: usize,
        value: Dyadic,
    },
    SeededPeriodic {
        dimension: usize,
        fractional_bits: u8,
        mantissas: Box<[i64]>,
    },
}

/// Allocation-free, sorted row iterator for any registered compiled family.
#[derive(Clone, Debug)]
pub struct MatrixRow<'a> {
    inner: MatrixRowInner<'a>,
}

#[derive(Clone, Debug)]
enum MatrixRowInner<'a> {
    Tridiagonal(TridiagonalMatrixRow),
    SymmetricDiaLaplacian(DiaMatrixRow<'a>),
    NonsymmetricRowSparse(NonsymmetricMatrixRow<'a>),
    ProjectedNonsymmetricRowSparse(ProjectedNonsymmetricMatrixRow<'a>),
}

#[derive(Clone, Debug)]
struct TridiagonalMatrixRow {
    entries: [MatrixEntry; 3],
    front: u8,
    back: u8,
}

impl TridiagonalMatrixRow {
    fn new(matrix: &PeriodicSymmetricTridiagonal, row: usize) -> Self {
        let empty = MatrixEntry {
            column: 0,
            value: Dyadic::new(0, matrix.fractional_bits),
        };
        let mut entries = [empty; 3];
        let mut len = 0_usize;
        let mut diagonal_mantissa = matrix.margin_mantissa;

        if row > 0 {
            let value = matrix.edge_mantissa(row - 1);
            diagonal_mantissa += value.unsigned_abs();
            entries[len] = MatrixEntry {
                column: row - 1,
                value: Dyadic::new(value, matrix.fractional_bits),
            };
            len += 1;
        }

        if row + 1 < matrix.dimension {
            diagonal_mantissa += matrix.edge_mantissa(row).unsigned_abs();
        }
        entries[len] = MatrixEntry {
            column: row,
            value: Dyadic::new(
                i64::try_from(diagonal_mantissa).expect("validated diagonal fits i64"),
                matrix.fractional_bits,
            ),
        };
        len += 1;

        if row + 1 < matrix.dimension {
            entries[len] = MatrixEntry {
                column: row + 1,
                value: Dyadic::new(matrix.edge_mantissa(row), matrix.fractional_bits),
            };
            len += 1;
        }

        Self {
            entries,
            front: 0,
            back: len as u8,
        }
    }
}

#[derive(Clone, Debug)]
struct DiaMatrixRow<'a> {
    matrix: &'a PeriodicSymmetricDiaLaplacian,
    row: usize,
    incoming_count: usize,
    diagonal_mantissa: i64,
    front: usize,
    back: usize,
}

impl<'a> DiaMatrixRow<'a> {
    fn new(matrix: &'a PeriodicSymmetricDiaLaplacian, row: usize) -> Self {
        let incoming_count = matrix
            .edges
            .partition_point(|edge| edge.positive_offset <= row);
        let outgoing_count = matrix
            .edges
            .partition_point(|edge| edge.positive_offset < matrix.dimension - row);
        let mut diagonal_mantissa = matrix.diagonal_shift_mantissa;
        for edge in &matrix.edges[..incoming_count] {
            diagonal_mantissa += matrix
                .edge_mantissa(edge, row - edge.positive_offset)
                .unsigned_abs();
        }
        for edge in &matrix.edges[..outgoing_count] {
            diagonal_mantissa += matrix.edge_mantissa(edge, row).unsigned_abs();
        }
        Self {
            matrix,
            row,
            incoming_count,
            diagonal_mantissa: i64::try_from(diagonal_mantissa)
                .expect("validated DIA diagonal fits i64"),
            front: 0,
            back: incoming_count + 1 + outgoing_count,
        }
    }

    fn entry_at(&self, position: usize) -> MatrixEntry {
        if position < self.incoming_count {
            let edge = &self.matrix.edges[self.incoming_count - 1 - position];
            let column = self.row - edge.positive_offset;
            return MatrixEntry {
                column,
                value: Dyadic::new(
                    self.matrix.edge_mantissa(edge, column),
                    self.matrix.fractional_bits,
                ),
            };
        }
        if position == self.incoming_count {
            return MatrixEntry {
                column: self.row,
                value: Dyadic::new(self.diagonal_mantissa, self.matrix.fractional_bits),
            };
        }
        let edge = &self.matrix.edges[position - self.incoming_count - 1];
        MatrixEntry {
            column: self.row + edge.positive_offset,
            value: Dyadic::new(
                self.matrix.edge_mantissa(edge, self.row),
                self.matrix.fractional_bits,
            ),
        }
    }
}

#[derive(Clone, Debug)]
struct NonsymmetricMatrixRow<'a> {
    matrix: &'a PeriodicNonsymmetricRowSparse,
    row: usize,
    pattern: usize,
    pattern_start: usize,
    valid_start: usize,
    diagonal_position: usize,
    front: usize,
    back: usize,
}

impl<'a> NonsymmetricMatrixRow<'a> {
    fn new(matrix: &'a PeriodicNonsymmetricRowSparse, row: usize) -> Self {
        let pattern = row & (matrix.period() - 1);
        let pattern_start = pattern * matrix.off_diagonals_per_pattern;
        let offsets = matrix.pattern_offsets(pattern);
        let minimum_offset = -i64::try_from(row).expect("validated row fits i64");
        let maximum_offset =
            i64::try_from(matrix.dimension - row).expect("validated dimension fits i64");
        let valid_start = offsets.partition_point(|&offset| i64::from(offset) < minimum_offset);
        let valid_end = offsets.partition_point(|&offset| i64::from(offset) < maximum_offset);
        let diagonal_position =
            offsets[valid_start..valid_end].partition_point(|&offset| offset < 0);
        Self {
            matrix,
            row,
            pattern,
            pattern_start,
            valid_start,
            diagonal_position,
            front: 0,
            back: valid_end - valid_start + 1,
        }
    }

    fn entry_at(&self, position: usize) -> MatrixEntry {
        if position == self.diagonal_position {
            return MatrixEntry {
                column: self.row,
                value: Dyadic::new(
                    self.matrix.diagonal_mantissas[self.pattern],
                    self.matrix.fractional_bits,
                ),
            };
        }
        let offset_position = if position < self.diagonal_position {
            self.valid_start + position
        } else {
            self.valid_start + position - 1
        };
        let table_index = self.pattern_start + offset_position;
        let signed_offset = self.matrix.signed_offsets[table_index];
        let column = self
            .row
            .checked_add_signed(
                isize::try_from(signed_offset).expect("validated signed offset fits isize"),
            )
            .expect("row constructor filtered boundary offsets");
        MatrixEntry {
            column,
            value: Dyadic::new(
                self.matrix.off_diagonal_mantissas[table_index],
                self.matrix.fractional_bits,
            ),
        }
    }
}

#[derive(Clone, Debug)]
struct ProjectedNonsymmetricMatrixRow<'a> {
    matrix: &'a ProjectedNonsymmetricRowSparse,
    row: usize,
    valid_start: usize,
    diagonal_position: usize,
    front: usize,
    back: usize,
}

impl<'a> ProjectedNonsymmetricMatrixRow<'a> {
    fn new(matrix: &'a ProjectedNonsymmetricRowSparse, row: usize) -> Self {
        let minimum_offset = -i64::try_from(row).expect("validated row fits i64");
        let maximum_offset =
            i64::try_from(matrix.dimension - row).expect("validated dimension fits i64");
        let mut valid_start = 0;
        while valid_start < matrix.off_diagonal_slots()
            && i64::from(matrix.row_signed_offset(row, valid_start)) < minimum_offset
        {
            valid_start += 1;
        }
        let mut diagonal_slot = valid_start;
        while diagonal_slot < matrix.off_diagonal_slots()
            && matrix.row_signed_offset(row, diagonal_slot) < 0
        {
            diagonal_slot += 1;
        }
        let mut valid_end = diagonal_slot;
        while valid_end < matrix.off_diagonal_slots()
            && i64::from(matrix.row_signed_offset(row, valid_end)) < maximum_offset
        {
            valid_end += 1;
        }
        let diagonal_position = diagonal_slot - valid_start;
        Self {
            matrix,
            row,
            valid_start,
            diagonal_position,
            front: 0,
            back: valid_end - valid_start + 1,
        }
    }

    fn entry_at(&self, position: usize) -> MatrixEntry {
        if position == self.diagonal_position {
            let pattern = self.matrix.row_pattern(self.row, 0);
            return MatrixEntry {
                column: self.row,
                value: Dyadic::new(
                    self.matrix.diagonal_mantissas[pattern],
                    self.matrix.fractional_bits,
                ),
            };
        }
        let slot = if position < self.diagonal_position {
            self.valid_start + position
        } else {
            self.valid_start + position - 1
        };
        let table_index = self.matrix.row_off_diagonal_table_index(self.row, slot);
        let signed_offset = self.matrix.signed_offsets[table_index];
        let column = self
            .row
            .checked_add_signed(
                isize::try_from(signed_offset).expect("validated signed offset fits isize"),
            )
            .expect("row constructor filtered boundary offsets");
        MatrixEntry {
            column,
            value: Dyadic::new(
                self.matrix.off_diagonal_mantissas[table_index],
                self.matrix.fractional_bits,
            ),
        }
    }
}

impl MatrixRow<'_> {
    fn tridiagonal(matrix: &PeriodicSymmetricTridiagonal, row: usize) -> Self {
        Self {
            inner: MatrixRowInner::Tridiagonal(TridiagonalMatrixRow::new(matrix, row)),
        }
    }

    fn dia(matrix: &PeriodicSymmetricDiaLaplacian, row: usize) -> MatrixRow<'_> {
        MatrixRow {
            inner: MatrixRowInner::SymmetricDiaLaplacian(DiaMatrixRow::new(matrix, row)),
        }
    }

    fn nonsymmetric(matrix: &PeriodicNonsymmetricRowSparse, row: usize) -> MatrixRow<'_> {
        MatrixRow {
            inner: MatrixRowInner::NonsymmetricRowSparse(NonsymmetricMatrixRow::new(matrix, row)),
        }
    }

    fn projected_nonsymmetric(
        matrix: &ProjectedNonsymmetricRowSparse,
        row: usize,
    ) -> MatrixRow<'_> {
        MatrixRow {
            inner: MatrixRowInner::ProjectedNonsymmetricRowSparse(
                ProjectedNonsymmetricMatrixRow::new(matrix, row),
            ),
        }
    }
}

impl Iterator for TridiagonalMatrixRow {
    type Item = MatrixEntry;

    fn next(&mut self) -> Option<Self::Item> {
        if self.front == self.back {
            return None;
        }
        let entry = self.entries[usize::from(self.front)];
        self.front += 1;
        Some(entry)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.len();
        (len, Some(len))
    }
}

impl DoubleEndedIterator for TridiagonalMatrixRow {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.front == self.back {
            return None;
        }
        self.back -= 1;
        Some(self.entries[usize::from(self.back)])
    }
}

impl ExactSizeIterator for TridiagonalMatrixRow {
    fn len(&self) -> usize {
        usize::from(self.back - self.front)
    }
}

impl FusedIterator for TridiagonalMatrixRow {}

impl Iterator for DiaMatrixRow<'_> {
    type Item = MatrixEntry;

    fn next(&mut self) -> Option<Self::Item> {
        if self.front == self.back {
            return None;
        }
        let entry = self.entry_at(self.front);
        self.front += 1;
        Some(entry)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.len();
        (len, Some(len))
    }
}

impl DoubleEndedIterator for DiaMatrixRow<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.front == self.back {
            return None;
        }
        self.back -= 1;
        Some(self.entry_at(self.back))
    }
}

impl ExactSizeIterator for DiaMatrixRow<'_> {
    fn len(&self) -> usize {
        self.back - self.front
    }
}

impl FusedIterator for DiaMatrixRow<'_> {}

impl Iterator for NonsymmetricMatrixRow<'_> {
    type Item = MatrixEntry;

    fn next(&mut self) -> Option<Self::Item> {
        if self.front == self.back {
            return None;
        }
        let entry = self.entry_at(self.front);
        self.front += 1;
        Some(entry)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.len();
        (len, Some(len))
    }
}

impl DoubleEndedIterator for NonsymmetricMatrixRow<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.front == self.back {
            return None;
        }
        self.back -= 1;
        Some(self.entry_at(self.back))
    }
}

impl ExactSizeIterator for NonsymmetricMatrixRow<'_> {
    fn len(&self) -> usize {
        self.back - self.front
    }
}

impl FusedIterator for NonsymmetricMatrixRow<'_> {}

impl Iterator for ProjectedNonsymmetricMatrixRow<'_> {
    type Item = MatrixEntry;

    fn next(&mut self) -> Option<Self::Item> {
        if self.front == self.back {
            return None;
        }
        let entry = self.entry_at(self.front);
        self.front += 1;
        Some(entry)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.len();
        (len, Some(len))
    }
}

impl DoubleEndedIterator for ProjectedNonsymmetricMatrixRow<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.front == self.back {
            return None;
        }
        self.back -= 1;
        Some(self.entry_at(self.back))
    }
}

impl ExactSizeIterator for ProjectedNonsymmetricMatrixRow<'_> {
    fn len(&self) -> usize {
        self.back - self.front
    }
}

impl FusedIterator for ProjectedNonsymmetricMatrixRow<'_> {}

impl Iterator for MatrixRow<'_> {
    type Item = MatrixEntry;

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.inner {
            MatrixRowInner::Tridiagonal(row) => row.next(),
            MatrixRowInner::SymmetricDiaLaplacian(row) => row.next(),
            MatrixRowInner::NonsymmetricRowSparse(row) => row.next(),
            MatrixRowInner::ProjectedNonsymmetricRowSparse(row) => row.next(),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.len();
        (len, Some(len))
    }
}

impl DoubleEndedIterator for MatrixRow<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        match &mut self.inner {
            MatrixRowInner::Tridiagonal(row) => row.next_back(),
            MatrixRowInner::SymmetricDiaLaplacian(row) => row.next_back(),
            MatrixRowInner::NonsymmetricRowSparse(row) => row.next_back(),
            MatrixRowInner::ProjectedNonsymmetricRowSparse(row) => row.next_back(),
        }
    }
}

impl ExactSizeIterator for MatrixRow<'_> {
    fn len(&self) -> usize {
        match &self.inner {
            MatrixRowInner::Tridiagonal(row) => row.len(),
            MatrixRowInner::SymmetricDiaLaplacian(row) => row.len(),
            MatrixRowInner::NonsymmetricRowSparse(row) => row.len(),
            MatrixRowInner::ProjectedNonsymmetricRowSparse(row) => row.len(),
        }
    }
}

impl FusedIterator for MatrixRow<'_> {}

/// Sequential row view that retains the same allocation-free row representation.
#[derive(Clone, Debug)]
pub struct MatrixRows<'a> {
    matrix: &'a CompiledMatrixFamily,
    next: usize,
}

impl<'a> Iterator for MatrixRows<'a> {
    type Item = MatrixRow<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next == self.matrix.dimension() {
            return None;
        }
        let row = self.next;
        self.next += 1;
        Some(self.matrix.row(row))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.len();
        (len, Some(len))
    }
}

impl ExactSizeIterator for MatrixRows<'_> {
    fn len(&self) -> usize {
        self.matrix.dimension() - self.next
    }
}

impl FusedIterator for MatrixRows<'_> {}

impl GeneratedProblem {
    pub(crate) fn compile(problem: &FinalizedProblem) -> Result<Self, ProblemError> {
        problem.validate()?;
        let problem_digest = problem.digest()?;
        let instance_seed = problem.instance_seed();
        let (matrix, matrix_facts) = compile_matrix(&problem.matrix, instance_seed)?;
        let rhs_seed = RhsSeed(derive_subseed(instance_seed, RHS_VALUES_LABEL));
        let rhs = compile_rhs(problem.rhs, matrix_facts.dimension, &matrix, rhs_seed)?;
        let (rhs_period, rhs_fractional_bits, maximum_absolute_rhs_mantissa) =
            rhs.certificate_values();
        let certificate = GeneratorCertificate {
            dimension: matrix_facts.dimension,
            structural_nonzeros: matrix_facts.structural_nonzeros,
            maximum_nonzeros_per_row: matrix_facts.maximum_nonzeros_per_row,
            maximum_half_bandwidth: matrix_facts.maximum_half_bandwidth,
            matrix_period: matrix_facts.matrix_period,
            coefficient_fractional_bits: matrix_facts.coefficient_fractional_bits,
            minimum_off_diagonal_magnitude_mantissa: matrix_facts
                .minimum_off_diagonal_magnitude_mantissa,
            maximum_off_diagonal_magnitude_mantissa: matrix_facts
                .maximum_off_diagonal_magnitude_mantissa,
            maximum_diagonal_mantissa_bound: matrix_facts.maximum_diagonal_mantissa_bound,
            maximum_absolute_row_sum_mantissa_bound: matrix_facts
                .maximum_absolute_row_sum_mantissa_bound,
            maximum_absolute_column_sum_mantissa_bound: matrix_facts
                .maximum_absolute_column_sum_mantissa_bound,
            strict_diagonal_dominance_margin_mantissa: matrix_facts
                .strict_diagonal_dominance_margin_mantissa,
            rhs_period,
            rhs_fractional_bits,
            maximum_absolute_rhs_mantissa,
            symmetric: matrix_facts.symmetric,
            positive_diagonal: matrix_facts.positive_diagonal,
            nonpositive_off_diagonal: matrix_facts.nonpositive_off_diagonal,
            strictly_row_diagonally_dominant: matrix_facts.strictly_row_diagonally_dominant,
            nonsingular_m_matrix: matrix_facts.nonsingular_m_matrix,
            boundary: matrix_facts.boundary,
        };

        Ok(Self {
            problem_digest,
            instance_seed,
            matrix,
            rhs,
            certificate,
        })
    }

    #[must_use]
    pub const fn problem_digest(&self) -> ProblemDigest {
        self.problem_digest
    }

    #[must_use]
    pub const fn instance_seed(&self) -> InstanceSeed {
        self.instance_seed
    }

    #[must_use]
    pub fn dimension(&self) -> usize {
        self.matrix.dimension()
    }

    #[must_use]
    pub const fn structural_nonzeros(&self) -> usize {
        self.certificate.structural_nonzeros
    }

    /// Alias matching the mathematical `nnz` abbreviation.
    #[must_use]
    pub const fn structural_nnz(&self) -> usize {
        self.structural_nonzeros()
    }

    #[must_use]
    pub const fn certificate(&self) -> &GeneratorCertificate {
        &self.certificate
    }

    #[must_use]
    pub fn row(&self, row: usize) -> Option<MatrixRow<'_>> {
        if row >= self.dimension() {
            return None;
        }
        Some(self.matrix.row(row))
    }

    #[must_use]
    pub fn rows(&self) -> MatrixRows<'_> {
        MatrixRows {
            matrix: &self.matrix,
            next: 0,
        }
    }

    #[must_use]
    pub fn rhs(&self, row: usize) -> Option<Dyadic> {
        self.rhs.value(row)
    }

    #[must_use]
    pub fn rhs_f64(&self, row: usize) -> Option<f64> {
        self.rhs(row).map(Dyadic::to_f64)
    }

    /// Flat generated matrix values in compiled-family order.
    ///
    /// The legacy tridiagonal has one table. DIA families concatenate one
    /// table per increasing positive-offset descriptor. The nonsymmetric
    /// v1 nonsymmetric rows store pattern-major off-diagonal values, while v2
    /// stores slot-major projected values. Their diagonal tables are
    /// intentionally separate and not returned here.
    #[must_use]
    pub fn off_diagonal_periodic_mantissas(&self) -> &[i64] {
        self.matrix.off_diagonal_mantissas()
    }

    /// Returns the seeded RHS table. Manufactured RHS values have no table.
    #[must_use]
    pub fn rhs_periodic_mantissas(&self) -> Option<&[i64]> {
        match &self.rhs {
            GeneratedRhs::ManufacturedOnes { .. } => None,
            GeneratedRhs::SeededPeriodic { mantissas, .. } => Some(mantissas),
        }
    }
}

impl SparseMatrix for GeneratedProblem {
    type Row<'a> = MatrixRow<'a>;

    fn dimension(&self) -> usize {
        self.dimension()
    }

    fn structural_nonzeros(&self) -> usize {
        self.structural_nonzeros()
    }

    fn row(&self, row: usize) -> Option<Self::Row<'_>> {
        self.row(row)
    }
}

impl PeriodicSymmetricTridiagonal {
    pub(crate) fn edge_mantissa(&self, lower_endpoint: usize) -> i64 {
        self.off_diagonal_mantissas[lower_endpoint & (self.off_diagonal_mantissas.len() - 1)]
    }
}

impl PeriodicSymmetricDiaLaplacian {
    pub(crate) fn edge_table<'a>(&'a self, edge: &DiaEdgeDescriptor) -> &'a [i64] {
        &self.off_diagonal_mantissas[edge.table_start..edge.table_start + edge.table_len]
    }

    pub(crate) fn edge_mantissa(&self, edge: &DiaEdgeDescriptor, anchor: usize) -> i64 {
        self.edge_table(edge)[anchor & (edge.table_len - 1)]
    }
}

impl PeriodicNonsymmetricRowSparse {
    pub(crate) fn period(&self) -> usize {
        self.diagonal_mantissas.len()
    }

    pub(crate) fn pattern_offsets(&self, pattern: usize) -> &[i32] {
        let start = pattern * self.off_diagonals_per_pattern;
        &self.signed_offsets[start..start + self.off_diagonals_per_pattern]
    }

    pub(crate) fn pattern_off_diagonal_mantissas(&self, pattern: usize) -> &[i64] {
        let start = pattern * self.off_diagonals_per_pattern;
        &self.off_diagonal_mantissas[start..start + self.off_diagonals_per_pattern]
    }
}

impl ProjectedNonsymmetricRowSparse {
    pub(crate) fn pattern_count(&self) -> usize {
        self.diagonal_mantissas.len()
    }

    pub(crate) fn off_diagonal_slots(&self) -> usize {
        self.row_width - 1
    }

    pub(crate) fn slot_projection(&self, slot: usize) -> &[u8] {
        let start = slot * self.pattern_bits;
        &self.projection_bits[start..start + self.pattern_bits]
    }

    pub(crate) fn row_pattern(&self, row: usize, slot: usize) -> usize {
        self.slot_projection(slot).iter().enumerate().fold(
            0_usize,
            |pattern, (pattern_bit, &row_bit)| {
                pattern | (((row >> usize::from(row_bit)) & 1) << pattern_bit)
            },
        )
    }

    pub(crate) fn off_diagonal_table_index(&self, slot: usize, pattern: usize) -> usize {
        slot * self.pattern_count() + pattern
    }

    fn row_off_diagonal_table_index(&self, row: usize, slot: usize) -> usize {
        let pattern = self.row_pattern(row, slot + 1);
        self.off_diagonal_table_index(slot, pattern)
    }

    fn row_signed_offset(&self, row: usize, slot: usize) -> i32 {
        self.signed_offsets[self.row_off_diagonal_table_index(row, slot)]
    }
}

impl CompiledMatrixFamily {
    pub(crate) fn dimension(&self) -> usize {
        match self {
            Self::Tridiagonal(matrix) => matrix.dimension,
            Self::SymmetricDiaLaplacian(matrix) => matrix.dimension,
            Self::NonsymmetricRowSparse(matrix) => matrix.dimension,
            Self::ProjectedNonsymmetricRowSparse(matrix) => matrix.dimension,
        }
    }

    fn row(&self, row: usize) -> MatrixRow<'_> {
        match self {
            Self::Tridiagonal(matrix) => MatrixRow::tridiagonal(matrix, row),
            Self::SymmetricDiaLaplacian(matrix) => MatrixRow::dia(matrix, row),
            Self::NonsymmetricRowSparse(matrix) => MatrixRow::nonsymmetric(matrix, row),
            Self::ProjectedNonsymmetricRowSparse(matrix) => {
                MatrixRow::projected_nonsymmetric(matrix, row)
            }
        }
    }

    pub(crate) const fn evaluator_version(&self) -> u16 {
        match self {
            Self::Tridiagonal(_) => 1,
            Self::SymmetricDiaLaplacian(_) => 2,
            Self::NonsymmetricRowSparse(_) => 3,
            Self::ProjectedNonsymmetricRowSparse(_) => 4,
        }
    }

    pub(crate) fn public_matrix_terms(
        &self,
        certificate: &GeneratorCertificate,
        padded_dimension: usize,
    ) -> usize {
        match self {
            Self::Tridiagonal(_) => certificate.matrix_period.min(padded_dimension),
            Self::SymmetricDiaLaplacian(_) => certificate.matrix_period,
            Self::NonsymmetricRowSparse(_) => certificate.matrix_period,
            Self::ProjectedNonsymmetricRowSparse(_) => certificate.matrix_period,
        }
    }

    fn manufactured_ones_value(&self) -> Option<Dyadic> {
        match self {
            Self::Tridiagonal(matrix) => Some(Dyadic::new(
                i64::try_from(matrix.margin_mantissa).expect("validated dominance margin fits i64"),
                matrix.fractional_bits,
            )),
            Self::SymmetricDiaLaplacian(matrix) => Some(Dyadic::new(
                i64::try_from(matrix.diagonal_shift_mantissa)
                    .expect("validated diagonal shift fits i64"),
                matrix.fractional_bits,
            )),
            Self::NonsymmetricRowSparse(_) | Self::ProjectedNonsymmetricRowSparse(_) => None,
        }
    }

    fn off_diagonal_mantissas(&self) -> &[i64] {
        match self {
            Self::Tridiagonal(matrix) => &matrix.off_diagonal_mantissas,
            Self::SymmetricDiaLaplacian(matrix) => &matrix.off_diagonal_mantissas,
            Self::NonsymmetricRowSparse(matrix) => &matrix.off_diagonal_mantissas,
            Self::ProjectedNonsymmetricRowSparse(matrix) => &matrix.off_diagonal_mantissas,
        }
    }
}

fn compile_matrix(
    spec: &MatrixSpec,
    instance_seed: InstanceSeed,
) -> Result<(CompiledMatrixFamily, MatrixFacts), ProblemError> {
    match spec {
        MatrixSpec::SeededSymmetricTridiagonalV1 {
            dimension,
            boundary,
            off_diagonal,
            diagonal,
        } => {
            let dimension = usize::try_from(*dimension)
                .map_err(|_| ProblemError::IntegerOverflow("compiled matrix dimension"))?;
            let (period_bits, fractional_bits, minimum_magnitude, maximum_magnitude) =
                off_diagonal.parameters();
            let matrix_period = 1_usize << period_bits;
            let matrix_seed = MatrixSeed(derive_subseed(instance_seed, MATRIX_VALUES_LABEL));
            let off_diagonal_mantissas = generate_negative_i64_table(
                matrix_seed.0,
                matrix_period,
                minimum_magnitude,
                maximum_magnitude,
            )?
            .into_boxed_slice();
            let maximum_generated_off_diagonal = off_diagonal_mantissas
                .iter()
                .map(|value| value.unsigned_abs())
                .max()
                .expect("validated period is nonempty");
            let minimum_generated_off_diagonal = off_diagonal_mantissas
                .iter()
                .map(|value| value.unsigned_abs())
                .min()
                .expect("validated period is nonempty");
            let margin_mantissa = diagonal.margin_mantissa();
            let maximum_diagonal_mantissa_bound = maximum_generated_off_diagonal
                .checked_mul(2)
                .and_then(|value| value.checked_add(margin_mantissa))
                .ok_or(ProblemError::IntegerOverflow("compiled diagonal bound"))?;
            let maximum_absolute_row_sum_mantissa_bound = maximum_generated_off_diagonal
                .checked_mul(4)
                .and_then(|value| value.checked_add(margin_mantissa))
                .ok_or(ProblemError::IntegerOverflow("compiled row-sum bound"))?;
            let matrix = PeriodicSymmetricTridiagonal {
                dimension,
                fractional_bits,
                margin_mantissa,
                off_diagonal_mantissas,
            };
            let facts = MatrixFacts {
                dimension,
                structural_nonzeros: tridiagonal_structural_nonzeros(dimension)?,
                maximum_nonzeros_per_row: if dimension == 2 { 2 } else { 3 },
                maximum_half_bandwidth: 1,
                matrix_period,
                coefficient_fractional_bits: fractional_bits,
                minimum_off_diagonal_magnitude_mantissa: minimum_generated_off_diagonal,
                maximum_off_diagonal_magnitude_mantissa: maximum_generated_off_diagonal,
                maximum_diagonal_mantissa_bound,
                maximum_absolute_row_sum_mantissa_bound,
                maximum_absolute_column_sum_mantissa_bound: maximum_absolute_row_sum_mantissa_bound,
                strict_diagonal_dominance_margin_mantissa: margin_mantissa,
                symmetric: true,
                positive_diagonal: true,
                nonpositive_off_diagonal: true,
                strictly_row_diagonally_dominant: true,
                nonsingular_m_matrix: true,
                boundary: *boundary,
            };
            Ok((CompiledMatrixFamily::Tridiagonal(matrix), facts))
        }
        MatrixSpec::SeededSymmetricDiaLaplacianV1 {
            dimension,
            boundary,
            fractional_bits,
            diagonal_shift_mantissa,
            edge_diagonals,
        } => {
            let dimension = usize::try_from(*dimension)
                .map_err(|_| ProblemError::IntegerOverflow("compiled DIA dimension"))?;
            let total_table_elements =
                edge_diagonals.iter().try_fold(0_usize, |total, edge| {
                    total.checked_add(1_usize << edge.period_bits).ok_or(
                        ProblemError::IntegerOverflow("compiled DIA periodic table elements"),
                    )
                })?;
            let mut descriptors = Vec::new();
            descriptors
                .try_reserve_exact(edge_diagonals.len())
                .map_err(|_| ProblemError::AllocationFailed)?;
            let mut off_diagonal_mantissas = Vec::new();
            off_diagonal_mantissas
                .try_reserve_exact(total_table_elements)
                .map_err(|_| ProblemError::AllocationFailed)?;

            let family_seed = MatrixSeed(derive_subseed(instance_seed, DIA_MATRIX_VALUES_LABEL));
            let mut structural_nonzeros = dimension;
            let mut matrix_period = 0_usize;
            let mut minimum_generated_weight = u64::MAX;
            let mut maximum_generated_weight = 0_u64;
            let mut maximum_incident_weight_bound = 0_u64;
            for (index, edge) in edge_diagonals.iter().enumerate() {
                let positive_offset = usize::try_from(edge.positive_offset)
                    .map_err(|_| ProblemError::IntegerOverflow("compiled DIA positive offset"))?;
                let table_len = 1_usize << edge.period_bits;
                let table_start = off_diagonal_mantissas.len();
                let edge_label = format!("edge-diagonal/{index}/offset/{}", edge.positive_offset);
                let edge_seed = MatrixSeed(derive_subseed(family_seed.0, &edge_label));
                append_negative_i64_table(
                    &mut off_diagonal_mantissas,
                    edge_seed.0,
                    table_len,
                    edge.minimum_weight_mantissa,
                    edge.maximum_weight_mantissa,
                )?;
                let table = &off_diagonal_mantissas[table_start..table_start + table_len];
                let generated_minimum = table
                    .iter()
                    .map(|value| value.unsigned_abs())
                    .min()
                    .expect("validated period is nonempty");
                let generated_maximum = table
                    .iter()
                    .map(|value| value.unsigned_abs())
                    .max()
                    .expect("validated period is nonempty");
                minimum_generated_weight = minimum_generated_weight.min(generated_minimum);
                maximum_generated_weight = maximum_generated_weight.max(generated_maximum);
                maximum_incident_weight_bound = generated_maximum
                    .checked_mul(2)
                    .and_then(|value| maximum_incident_weight_bound.checked_add(value))
                    .ok_or(ProblemError::IntegerOverflow(
                        "compiled DIA incident-weight bound",
                    ))?;
                let edge_count = dimension
                    .checked_sub(positive_offset)
                    .ok_or(ProblemError::IntegerOverflow("compiled DIA edge count"))?;
                structural_nonzeros = edge_count
                    .checked_mul(2)
                    .and_then(|count| structural_nonzeros.checked_add(count))
                    .ok_or(ProblemError::IntegerOverflow(
                        "compiled DIA structural nonzeros",
                    ))?;
                matrix_period = matrix_period.checked_add(table_len.min(edge_count)).ok_or(
                    ProblemError::IntegerOverflow("compiled DIA public evaluation terms"),
                )?;
                descriptors.push(DiaEdgeDescriptor {
                    positive_offset,
                    table_start,
                    table_len,
                });
            }
            let maximum_diagonal_mantissa_bound = maximum_incident_weight_bound
                .checked_add(*diagonal_shift_mantissa)
                .ok_or(ProblemError::IntegerOverflow("compiled DIA diagonal bound"))?;
            let maximum_absolute_row_sum_mantissa_bound = maximum_incident_weight_bound
                .checked_mul(2)
                .and_then(|value| value.checked_add(*diagonal_shift_mantissa))
                .ok_or(ProblemError::IntegerOverflow("compiled DIA row-sum bound"))?;
            let maximum_nonzeros_per_row =
                u8::try_from(1 + 2 * descriptors.len()).expect("validated DIA edge count fits u8");
            let maximum_half_bandwidth = descriptors
                .last()
                .expect("validated DIA edge descriptors are nonempty")
                .positive_offset;
            let matrix = PeriodicSymmetricDiaLaplacian {
                dimension,
                fractional_bits: *fractional_bits,
                diagonal_shift_mantissa: *diagonal_shift_mantissa,
                edges: descriptors.into_boxed_slice(),
                off_diagonal_mantissas: off_diagonal_mantissas.into_boxed_slice(),
            };
            let facts = MatrixFacts {
                dimension,
                structural_nonzeros,
                maximum_nonzeros_per_row,
                maximum_half_bandwidth,
                matrix_period,
                coefficient_fractional_bits: *fractional_bits,
                minimum_off_diagonal_magnitude_mantissa: minimum_generated_weight,
                maximum_off_diagonal_magnitude_mantissa: maximum_generated_weight,
                maximum_diagonal_mantissa_bound,
                maximum_absolute_row_sum_mantissa_bound,
                maximum_absolute_column_sum_mantissa_bound: maximum_absolute_row_sum_mantissa_bound,
                strict_diagonal_dominance_margin_mantissa: *diagonal_shift_mantissa,
                symmetric: true,
                positive_diagonal: true,
                nonpositive_off_diagonal: true,
                strictly_row_diagonally_dominant: true,
                nonsingular_m_matrix: true,
                boundary: *boundary,
            };
            Ok((CompiledMatrixFamily::SymmetricDiaLaplacian(matrix), facts))
        }
        MatrixSpec::SeededNonsymmetricRowSparseV1 {
            dimension,
            boundary,
            row_pattern_bits,
            maximum_half_bandwidth,
            maximum_nonzeros_per_row,
            fractional_bits,
            minimum_mantissa,
            maximum_mantissa,
        } => {
            let dimension = usize::try_from(*dimension).map_err(|_| {
                ProblemError::IntegerOverflow("compiled nonsymmetric matrix dimension")
            })?;
            let maximum_half_bandwidth =
                usize::try_from(*maximum_half_bandwidth).map_err(|_| {
                    ProblemError::IntegerOverflow("compiled nonsymmetric half bandwidth")
                })?;
            let requested_period = 1_usize << *row_pattern_bits;
            let period = requested_period.min(dimension.next_power_of_two());
            let row_width = usize::from(*maximum_nonzeros_per_row);
            let off_diagonals_per_pattern = row_width - 1;
            let total_off_diagonals = period.checked_mul(off_diagonals_per_pattern).ok_or(
                ProblemError::IntegerOverflow("compiled nonsymmetric periodic entries"),
            )?;

            let mut signed_offsets = Vec::new();
            signed_offsets
                .try_reserve_exact(total_off_diagonals)
                .map_err(|_| ProblemError::AllocationFailed)?;
            let structure_seed = derive_subseed(instance_seed, NONSYMMETRIC_STRUCTURE_LABEL);
            let mut structure_stream = UniformStream::new(structure_seed);
            for _ in 0..period {
                append_sampled_signed_offsets(
                    &mut signed_offsets,
                    &mut structure_stream,
                    maximum_half_bandwidth,
                    off_diagonals_per_pattern,
                );
            }

            let mut off_diagonal_mantissas = Vec::new();
            off_diagonal_mantissas
                .try_reserve_exact(total_off_diagonals)
                .map_err(|_| ProblemError::AllocationFailed)?;
            let off_diagonal_seed =
                derive_subseed(instance_seed, NONSYMMETRIC_OFF_DIAGONAL_VALUES_LABEL);
            let mut off_diagonal_stream = UniformStream::new(off_diagonal_seed);
            for _ in 0..total_off_diagonals {
                off_diagonal_mantissas.push(sample_nonzero_mantissa(
                    &mut off_diagonal_stream,
                    *minimum_mantissa,
                    *maximum_mantissa,
                ));
            }

            let mut diagonal_mantissas = Vec::new();
            diagonal_mantissas
                .try_reserve_exact(period)
                .map_err(|_| ProblemError::AllocationFailed)?;
            let diagonal_seed = derive_subseed(instance_seed, NONSYMMETRIC_DIAGONAL_VALUES_LABEL);
            let mut diagonal_stream = UniformStream::new(diagonal_seed);
            for _ in 0..period {
                diagonal_mantissas.push(sample_nonzero_mantissa(
                    &mut diagonal_stream,
                    *minimum_mantissa,
                    *maximum_mantissa,
                ));
            }

            let active_patterns = period.min(dimension);
            let mut structural_nonzeros = dimension;
            for pattern in 0..active_patterns {
                let start = pattern * off_diagonals_per_pattern;
                let end = start + off_diagonals_per_pattern;
                for &signed_offset in &signed_offsets[start..end] {
                    structural_nonzeros = structural_nonzeros
                        .checked_add(periodic_offset_count(
                            dimension,
                            period,
                            pattern,
                            signed_offset,
                        ))
                        .ok_or(ProblemError::IntegerOverflow(
                            "compiled nonsymmetric structural nonzeros",
                        ))?;
                }
            }

            let maximum_off_diagonal = off_diagonal_mantissas
                .iter()
                .map(|value| value.unsigned_abs())
                .max()
                .unwrap_or(0);
            let minimum_off_diagonal = off_diagonal_mantissas
                .iter()
                .map(|value| value.unsigned_abs())
                .min()
                .unwrap_or(0);
            let maximum_diagonal = diagonal_mantissas
                .iter()
                .map(|value| value.unsigned_abs())
                .max()
                .expect("validated nonsymmetric period is nonempty");
            let maximum_absolute_row_sum_mantissa_bound = maximum_off_diagonal
                .checked_mul(
                    u64::try_from(off_diagonals_per_pattern).expect("validated row width fits u64"),
                )
                .and_then(|value| value.checked_add(maximum_diagonal))
                .ok_or(ProblemError::IntegerOverflow(
                    "compiled nonsymmetric row-sum bound",
                ))?;
            let bandwidth_source_bound = maximum_half_bandwidth
                .checked_mul(2)
                .expect("validated half bandwidth source bound fits usize");
            let possible_off_diagonal_sources = (dimension - 1).min(bandwidth_source_bound);
            let maximum_absolute_column_sum_mantissa_bound = maximum_off_diagonal
                .checked_mul(
                    u64::try_from(possible_off_diagonal_sources)
                        .expect("validated column-source count fits u64"),
                )
                .and_then(|value| value.checked_add(maximum_diagonal))
                .ok_or(ProblemError::IntegerOverflow(
                    "compiled nonsymmetric column-sum bound",
                ))?;
            let matrix_period =
                active_patterns
                    .checked_mul(row_width)
                    .ok_or(ProblemError::IntegerOverflow(
                        "compiled nonsymmetric public evaluation terms",
                    ))?;
            let positive_diagonal = diagonal_mantissas.iter().all(|value| *value > 0);
            let nonpositive_off_diagonal = off_diagonal_mantissas.iter().all(|value| *value < 0);
            let matrix = PeriodicNonsymmetricRowSparse {
                dimension,
                fractional_bits: *fractional_bits,
                off_diagonals_per_pattern,
                signed_offsets: signed_offsets.into_boxed_slice(),
                off_diagonal_mantissas: off_diagonal_mantissas.into_boxed_slice(),
                diagonal_mantissas: diagonal_mantissas.into_boxed_slice(),
            };
            let facts = MatrixFacts {
                dimension,
                structural_nonzeros,
                maximum_nonzeros_per_row: *maximum_nonzeros_per_row,
                maximum_half_bandwidth,
                matrix_period,
                coefficient_fractional_bits: *fractional_bits,
                minimum_off_diagonal_magnitude_mantissa: minimum_off_diagonal,
                maximum_off_diagonal_magnitude_mantissa: maximum_off_diagonal,
                maximum_diagonal_mantissa_bound: maximum_diagonal,
                maximum_absolute_row_sum_mantissa_bound,
                maximum_absolute_column_sum_mantissa_bound,
                strict_diagonal_dominance_margin_mantissa: 0,
                symmetric: false,
                positive_diagonal,
                nonpositive_off_diagonal,
                strictly_row_diagonally_dominant: false,
                nonsingular_m_matrix: false,
                boundary: *boundary,
            };
            Ok((CompiledMatrixFamily::NonsymmetricRowSparse(matrix), facts))
        }
        MatrixSpec::SeededNonsymmetricRowSparseV2 { .. } => {
            compile_projected_nonsymmetric(spec, instance_seed)
        }
    }
}

fn compile_projected_nonsymmetric(
    spec: &MatrixSpec,
    instance_seed: InstanceSeed,
) -> Result<(CompiledMatrixFamily, MatrixFacts), ProblemError> {
    let MatrixSpec::SeededNonsymmetricRowSparseV2 {
        dimension,
        boundary,
        row_pattern_bits,
        maximum_half_bandwidth,
        maximum_nonzeros_per_row,
        fractional_bits,
        minimum_mantissa,
        maximum_mantissa,
    } = spec
    else {
        unreachable!("projected compiler called for another matrix family")
    };
    let dimension = usize::try_from(*dimension).map_err(|_| {
        ProblemError::IntegerOverflow("compiled projected nonsymmetric matrix dimension")
    })?;
    let maximum_half_bandwidth = usize::try_from(*maximum_half_bandwidth).map_err(|_| {
        ProblemError::IntegerOverflow("compiled projected nonsymmetric half bandwidth")
    })?;
    let row_width = usize::from(*maximum_nonzeros_per_row);
    let off_diagonal_slots = row_width - 1;
    let row_index_bits = dimension.next_power_of_two().ilog2() as usize;
    let pattern_bits = usize::from(*row_pattern_bits).min(row_index_bits);
    let pattern_count = 1_usize << pattern_bits;
    let total_off_diagonals =
        pattern_count
            .checked_mul(off_diagonal_slots)
            .ok_or(ProblemError::IntegerOverflow(
                "compiled projected nonsymmetric table entries",
            ))?;

    let projection_seed = derive_subseed(instance_seed, PROJECTED_NONSYMMETRIC_PROJECTIONS_LABEL);
    let mut projection_stream = UniformStream::new(projection_seed);
    let mut row_bit_permutation = Vec::new();
    row_bit_permutation
        .try_reserve_exact(row_index_bits)
        .map_err(|_| ProblemError::AllocationFailed)?;
    for bit in 0..row_index_bits {
        row_bit_permutation.push(u8::try_from(bit).expect("validated row bit fits u8"));
    }
    for upper in (1..row_index_bits).rev() {
        let selected = usize::try_from(
            projection_stream
                .sample_below(u64::try_from(upper + 1).expect("row-index bit count fits u64")),
        )
        .expect("sampled row-index bit fits usize");
        row_bit_permutation.swap(upper, selected);
    }
    let projection_elements =
        row_width
            .checked_mul(pattern_bits)
            .ok_or(ProblemError::IntegerOverflow(
                "compiled projected row-bit positions",
            ))?;
    let mut projection_bits = Vec::new();
    projection_bits
        .try_reserve_exact(projection_elements)
        .map_err(|_| ProblemError::AllocationFailed)?;
    for slot in 0..row_width {
        let window_start = slot * pattern_bits;
        let rotation = slot % pattern_bits;
        for pattern_bit in 0..pattern_bits {
            let within_window = (pattern_bit + rotation) % pattern_bits;
            projection_bits
                .push(row_bit_permutation[(window_start + within_window) % row_index_bits]);
        }
    }
    debug_assert!((0..row_index_bits).all(|bit| {
        projection_bits
            .iter()
            .any(|&projected| usize::from(projected) == bit)
    }));

    let buckets = projected_offset_buckets(maximum_half_bandwidth, off_diagonal_slots)?;
    let structure_seed = derive_subseed(instance_seed, PROJECTED_NONSYMMETRIC_STRUCTURE_LABEL);
    let mut structure_stream = UniformStream::new(structure_seed);
    let mut signed_offsets = Vec::new();
    signed_offsets
        .try_reserve_exact(total_off_diagonals)
        .map_err(|_| ProblemError::AllocationFailed)?;
    for bucket in &buckets {
        for _ in 0..pattern_count {
            let population_index = bucket.start + structure_stream.sample_below(bucket.len);
            signed_offsets.push(signed_offset_from_population_index(
                population_index,
                maximum_half_bandwidth,
            ));
        }
    }

    let off_diagonal_seed = derive_subseed(
        instance_seed,
        PROJECTED_NONSYMMETRIC_OFF_DIAGONAL_VALUES_LABEL,
    );
    let mut off_diagonal_stream = UniformStream::new(off_diagonal_seed);
    let mut off_diagonal_mantissas = Vec::new();
    off_diagonal_mantissas
        .try_reserve_exact(total_off_diagonals)
        .map_err(|_| ProblemError::AllocationFailed)?;
    for _ in 0..total_off_diagonals {
        off_diagonal_mantissas.push(sample_nonzero_mantissa(
            &mut off_diagonal_stream,
            *minimum_mantissa,
            *maximum_mantissa,
        ));
    }

    let diagonal_seed = derive_subseed(instance_seed, PROJECTED_NONSYMMETRIC_DIAGONAL_VALUES_LABEL);
    let mut diagonal_stream = UniformStream::new(diagonal_seed);
    let mut diagonal_mantissas = Vec::new();
    diagonal_mantissas
        .try_reserve_exact(pattern_count)
        .map_err(|_| ProblemError::AllocationFailed)?;
    for _ in 0..pattern_count {
        diagonal_mantissas.push(sample_nonzero_mantissa(
            &mut diagonal_stream,
            *minimum_mantissa,
            *maximum_mantissa,
        ));
    }

    let mut structural_nonzeros = dimension;
    for slot in 0..off_diagonal_slots {
        let projection_start = (slot + 1) * pattern_bits;
        let projection = &projection_bits[projection_start..projection_start + pattern_bits];
        for pattern in 0..pattern_count {
            let table_index = slot * pattern_count + pattern;
            structural_nonzeros = structural_nonzeros
                .checked_add(projected_offset_count(
                    dimension,
                    row_index_bits,
                    projection,
                    pattern,
                    signed_offsets[table_index],
                ))
                .ok_or(ProblemError::IntegerOverflow(
                    "compiled projected nonsymmetric structural nonzeros",
                ))?;
        }
    }

    let maximum_off_diagonal = off_diagonal_mantissas
        .iter()
        .map(|value| value.unsigned_abs())
        .max()
        .unwrap_or(0);
    let minimum_off_diagonal = off_diagonal_mantissas
        .iter()
        .map(|value| value.unsigned_abs())
        .min()
        .unwrap_or(0);
    let maximum_diagonal = diagonal_mantissas
        .iter()
        .map(|value| value.unsigned_abs())
        .max()
        .expect("validated projected nonsymmetric pattern table is nonempty");
    let maximum_absolute_row_sum_mantissa_bound = maximum_off_diagonal
        .checked_mul(
            u64::try_from(off_diagonal_slots).expect("validated projected row width fits u64"),
        )
        .and_then(|value| value.checked_add(maximum_diagonal))
        .ok_or(ProblemError::IntegerOverflow(
            "compiled projected nonsymmetric row-sum bound",
        ))?;
    let bandwidth_source_bound = maximum_half_bandwidth
        .checked_mul(2)
        .expect("validated projected half bandwidth source bound fits usize");
    let possible_off_diagonal_sources = (dimension - 1).min(bandwidth_source_bound);
    let maximum_absolute_column_sum_mantissa_bound = maximum_off_diagonal
        .checked_mul(
            u64::try_from(possible_off_diagonal_sources)
                .expect("validated projected column-source count fits u64"),
        )
        .and_then(|value| value.checked_add(maximum_diagonal))
        .ok_or(ProblemError::IntegerOverflow(
            "compiled projected nonsymmetric column-sum bound",
        ))?;
    let matrix_period =
        pattern_count
            .checked_mul(row_width)
            .ok_or(ProblemError::IntegerOverflow(
                "compiled projected nonsymmetric public evaluation terms",
            ))?;
    let positive_diagonal = diagonal_mantissas.iter().all(|value| *value > 0);
    let nonpositive_off_diagonal = off_diagonal_mantissas.iter().all(|value| *value < 0);
    let matrix = ProjectedNonsymmetricRowSparse {
        dimension,
        fractional_bits: *fractional_bits,
        pattern_bits,
        row_width,
        projection_bits: projection_bits.into_boxed_slice(),
        signed_offsets: signed_offsets.into_boxed_slice(),
        off_diagonal_mantissas: off_diagonal_mantissas.into_boxed_slice(),
        diagonal_mantissas: diagonal_mantissas.into_boxed_slice(),
    };
    let facts = MatrixFacts {
        dimension,
        structural_nonzeros,
        maximum_nonzeros_per_row: *maximum_nonzeros_per_row,
        maximum_half_bandwidth,
        matrix_period,
        coefficient_fractional_bits: *fractional_bits,
        minimum_off_diagonal_magnitude_mantissa: minimum_off_diagonal,
        maximum_off_diagonal_magnitude_mantissa: maximum_off_diagonal,
        maximum_diagonal_mantissa_bound: maximum_diagonal,
        maximum_absolute_row_sum_mantissa_bound,
        maximum_absolute_column_sum_mantissa_bound,
        strict_diagonal_dominance_margin_mantissa: 0,
        symmetric: false,
        positive_diagonal,
        nonpositive_off_diagonal,
        strictly_row_diagonally_dominant: false,
        nonsingular_m_matrix: false,
        boundary: *boundary,
    };
    Ok((
        CompiledMatrixFamily::ProjectedNonsymmetricRowSparse(matrix),
        facts,
    ))
}

impl GeneratedRhs {
    fn value(&self, row: usize) -> Option<Dyadic> {
        match self {
            Self::ManufacturedOnes { dimension, value } => (row < *dimension).then_some(*value),
            Self::SeededPeriodic {
                dimension,
                fractional_bits,
                mantissas,
            } => (row < *dimension)
                .then(|| Dyadic::new(mantissas[row & (mantissas.len() - 1)], *fractional_bits)),
        }
    }

    fn certificate_values(&self) -> (usize, u8, u64) {
        match self {
            Self::ManufacturedOnes { value, .. } => {
                (1, value.fractional_bits(), value.mantissa().unsigned_abs())
            }
            Self::SeededPeriodic {
                fractional_bits,
                mantissas,
                ..
            } => (
                mantissas.len(),
                *fractional_bits,
                mantissas
                    .iter()
                    .map(|value| value.unsigned_abs())
                    .max()
                    .expect("validated period is nonempty"),
            ),
        }
    }
}

fn compile_rhs(
    spec: RhsSpec,
    dimension: usize,
    matrix: &CompiledMatrixFamily,
    seed: RhsSeed,
) -> Result<GeneratedRhs, ProblemError> {
    match spec {
        RhsSpec::ManufacturedOnesV1 => {
            let value = matrix
                .manufactured_ones_value()
                .ok_or(ProblemError::UnsupportedManufacturedRhs)?;
            Ok(GeneratedRhs::ManufacturedOnes { dimension, value })
        }
        RhsSpec::SeededPeriodicDyadicV1 {
            period_bits,
            fractional_bits,
            minimum_mantissa,
            maximum_mantissa,
        } => {
            let period = 1_usize << period_bits;
            let width =
                u64::try_from(i128::from(maximum_mantissa) - i128::from(minimum_mantissa) + 1)
                    .map_err(|_| ProblemError::RhsRangeTooWide)?;
            let mut stream = UniformStream::new(seed.0);
            let mut mantissas = Vec::new();
            mantissas
                .try_reserve_exact(period)
                .map_err(|_| ProblemError::AllocationFailed)?;
            for _ in 0..period {
                let offset = stream.sample_below(width);
                let value = i128::from(minimum_mantissa) + i128::from(offset);
                mantissas.push(i64::try_from(value).expect("validated RHS range fits i64"));
            }
            Ok(GeneratedRhs::SeededPeriodic {
                dimension,
                fractional_bits,
                mantissas: mantissas.into_boxed_slice(),
            })
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OffsetBucket {
    start: u64,
    len: u64,
}

/// Builds increasing, disjoint offset buckets for projected row slots.
///
/// The `+1` bucket is always present when an off-diagonal was requested. This
/// prevents a residue-class decomposition caused by every generated offset
/// sharing a nontrivial divisor. Remaining slots cover balanced partitions of
/// the negative offsets and, when capacity permits, positive offsets above one.
fn projected_offset_buckets(
    half_bandwidth: usize,
    off_diagonal_slots: usize,
) -> Result<Vec<OffsetBucket>, ProblemError> {
    if off_diagonal_slots == 0 {
        return Ok(Vec::new());
    }
    debug_assert!(half_bandwidth > 0);
    debug_assert!(off_diagonal_slots <= 2 * half_bandwidth);

    let remaining_slots = off_diagonal_slots - 1;
    let positive_capacity = half_bandwidth - 1;
    let minimum_negative_slots = remaining_slots.saturating_sub(positive_capacity);
    let maximum_negative_slots = remaining_slots.min(half_bandwidth);
    let balanced_negative_slots = remaining_slots.div_ceil(2);
    let negative_slots =
        balanced_negative_slots.clamp(minimum_negative_slots, maximum_negative_slots);
    let positive_slots = remaining_slots - negative_slots;

    let mut buckets = Vec::new();
    buckets
        .try_reserve_exact(off_diagonal_slots)
        .map_err(|_| ProblemError::AllocationFailed)?;
    append_offset_partition(&mut buckets, 0, half_bandwidth, negative_slots);
    buckets.push(OffsetBucket {
        start: u64::try_from(half_bandwidth).expect("validated half bandwidth fits u64"),
        len: 1,
    });
    append_offset_partition(
        &mut buckets,
        half_bandwidth + 1,
        positive_capacity,
        positive_slots,
    );
    debug_assert_eq!(buckets.len(), off_diagonal_slots);
    Ok(buckets)
}

fn append_offset_partition(
    buckets: &mut Vec<OffsetBucket>,
    population_start: usize,
    population_len: usize,
    parts: usize,
) {
    if parts == 0 {
        return;
    }
    debug_assert!(parts <= population_len);
    let base_len = population_len / parts;
    let longer_parts = population_len % parts;
    let mut start = population_start;
    for part in 0..parts {
        let len = base_len + usize::from(part < longer_parts);
        buckets.push(OffsetBucket {
            start: u64::try_from(start).expect("validated offset bucket start fits u64"),
            len: u64::try_from(len).expect("validated offset bucket length fits u64"),
        });
        start += len;
    }
    debug_assert_eq!(start, population_start + population_len);
}

fn projected_offset_count(
    dimension: usize,
    row_index_bits: usize,
    projection: &[u8],
    pattern: usize,
    signed_offset: i32,
) -> usize {
    let (lower, upper) = if signed_offset < 0 {
        (
            usize::try_from(signed_offset.unsigned_abs())
                .expect("validated projected offset magnitude fits usize"),
            dimension,
        )
    } else {
        (
            0,
            dimension
                - usize::try_from(signed_offset)
                    .expect("validated projected nonnegative offset fits usize"),
        )
    };
    projected_index_count(upper, row_index_bits, projection, pattern)
        - projected_index_count(lower, row_index_bits, projection, pattern)
}

/// Counts bounded indices selected by one arbitrary row-bit projection.
///
/// The two states track the borrow from subtracting `limit`, least-significant
/// bit first. This is the integer counterpart of the public-MLE digit program
/// and runs in `O(log(dimension) * projection.len())` without visiting rows.
fn projected_index_count(
    limit: usize,
    row_index_bits: usize,
    projection: &[u8],
    pattern: usize,
) -> usize {
    let domain = 1_usize << row_index_bits;
    debug_assert!(limit <= domain);
    debug_assert!(pattern < (1_usize << projection.len()));
    let mut states = [1_usize, 0_usize];
    for bit in 0..row_index_bits {
        let limit_bit = (limit >> bit) & 1;
        let required_bit = projection
            .iter()
            .position(|&projected| usize::from(projected) == bit)
            .map(|pattern_bit| (pattern >> pattern_bit) & 1);
        let mut next = [0_usize; 2];
        for (borrow_in, count) in states.into_iter().enumerate() {
            for index_bit in 0..=1 {
                if required_bit.is_some_and(|required| index_bit != required) {
                    continue;
                }
                let borrow_out = usize::from(index_bit < limit_bit + borrow_in);
                next[borrow_out] += count;
            }
        }
        states = next;
    }
    states[usize::from(limit < domain)]
}

/// Appends one uniformly sampled subset of nonzero signed offsets, sorted by
/// column displacement. Floyd's algorithm uses `O(count^2)` comparisons over
/// the bounded row width and never allocates a bandwidth-sized candidate set.
fn append_sampled_signed_offsets(
    offsets: &mut Vec<i32>,
    stream: &mut UniformStream,
    half_bandwidth: usize,
    count: usize,
) {
    let start = offsets.len();
    let population = u64::try_from(half_bandwidth)
        .expect("validated half bandwidth fits u64")
        .checked_mul(2)
        .expect("validated offset population fits u64");
    let count = u64::try_from(count).expect("validated row width fits u64");
    debug_assert!(count <= population);
    for upper in population - count..population {
        let candidate = stream.sample_below(upper + 1);
        let candidate = signed_offset_from_population_index(candidate, half_bandwidth);
        let selected = if offsets[start..].contains(&candidate) {
            signed_offset_from_population_index(upper, half_bandwidth)
        } else {
            candidate
        };
        offsets.push(selected);
    }
    offsets[start..].sort_unstable();
}

fn signed_offset_from_population_index(index: u64, half_bandwidth: usize) -> i32 {
    let half_bandwidth = i64::try_from(half_bandwidth)
        .expect("validated half bandwidth fits signed offset representation");
    let index = i64::try_from(index).expect("validated offset index fits i64");
    let signed = if index < half_bandwidth {
        index - half_bandwidth
    } else {
        index - half_bandwidth + 1
    };
    i32::try_from(signed).expect("validated signed offset fits i32")
}

fn sample_nonzero_mantissa(stream: &mut UniformStream, minimum: i64, maximum: i64) -> i64 {
    let contains_zero = minimum <= 0 && maximum >= 0;
    let inclusive_width = i128::from(maximum) - i128::from(minimum) + 1;
    let nonzero_width = inclusive_width - i128::from(contains_zero);
    let sample = i128::from(stream.sample_below(
        u64::try_from(nonzero_width).expect("validated nonzero coefficient range fits u64"),
    ));
    let value = if contains_zero {
        let negative_values = i128::from(minimum).unsigned_abs();
        if sample < i128::try_from(negative_values).expect("negative range width fits i128") {
            i128::from(minimum) + sample
        } else {
            1 + sample - i128::try_from(negative_values).expect("negative range width fits i128")
        }
    } else {
        i128::from(minimum) + sample
    };
    i64::try_from(value).expect("validated coefficient range fits i64")
}

fn periodic_offset_count(
    dimension: usize,
    period: usize,
    pattern: usize,
    signed_offset: i32,
) -> usize {
    let (lower, upper) = if signed_offset < 0 {
        (
            usize::try_from(signed_offset.unsigned_abs())
                .expect("validated offset magnitude fits usize"),
            dimension,
        )
    } else {
        (
            0,
            dimension - usize::try_from(signed_offset).expect("nonnegative offset fits usize"),
        )
    };
    periodic_index_count(upper, period, pattern) - periodic_index_count(lower, period, pattern)
}

fn periodic_index_count(limit: usize, period: usize, pattern: usize) -> usize {
    if pattern >= limit {
        0
    } else {
        1 + (limit - 1 - pattern) / period
    }
}

fn generate_negative_i64_table(
    seed: InstanceSeed,
    period: usize,
    minimum: u64,
    maximum: u64,
) -> Result<Vec<i64>, ProblemError> {
    let width = maximum
        .checked_sub(minimum)
        .and_then(|value| value.checked_add(1))
        .ok_or(ProblemError::IntegerOverflow("generator sample interval"))?;
    let mut stream = UniformStream::new(seed);
    let mut table = Vec::new();
    table
        .try_reserve_exact(period)
        .map_err(|_| ProblemError::AllocationFailed)?;
    for _ in 0..period {
        let magnitude = minimum + stream.sample_below(width);
        table.push(-i64::try_from(magnitude).expect("validated off-diagonal magnitude fits i64"));
    }
    Ok(table)
}

fn append_negative_i64_table(
    table: &mut Vec<i64>,
    seed: InstanceSeed,
    period: usize,
    minimum: u64,
    maximum: u64,
) -> Result<(), ProblemError> {
    let width = maximum
        .checked_sub(minimum)
        .and_then(|value| value.checked_add(1))
        .ok_or(ProblemError::IntegerOverflow("generator sample interval"))?;
    let mut stream = UniformStream::new(seed);
    for _ in 0..period {
        let magnitude = minimum + stream.sample_below(width);
        table.push(-i64::try_from(magnitude).expect("validated edge weight fits i64"));
    }
    Ok(())
}

fn tridiagonal_structural_nonzeros(dimension: usize) -> Result<usize, ProblemError> {
    dimension
        .checked_mul(3)
        .and_then(|value| value.checked_sub(2))
        .ok_or(ProblemError::IntegerOverflow("structural nonzero count"))
}

/// BLAKE3 XOF words mapped with rejection sampling, never modulo-biased.
struct UniformStream {
    reader: OutputReader,
}

impl UniformStream {
    fn new(seed: InstanceSeed) -> Self {
        let mut hasher = blake3::Hasher::new_derive_key(UNBIASED_STREAM_CONTEXT);
        hasher.update(seed.as_bytes());
        Self {
            reader: hasher.finalize_xof(),
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0_u8; 8];
        self.reader.fill(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn sample_below(&mut self, bound: u64) -> u64 {
        debug_assert!(bound > 0);
        let rejection_threshold = bound.wrapping_neg() % bound;
        loop {
            let candidate = self.next_u64();
            if candidate >= rejection_threshold {
                return candidate % bound;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::{
        DiagonalConstruction, MatrixSpec, OffDiagonalValues, ProblemSchema, ProblemTemplate,
        RequestedOutput, SeedDerivation, SymmetricDiaEdge, TemplateRandomness, TemplateSchema,
    };

    fn matrix(dimension: u64) -> MatrixSpec {
        MatrixSpec::SeededSymmetricTridiagonalV1 {
            dimension,
            boundary: BoundaryRule::TruncateV1,
            off_diagonal: OffDiagonalValues::SeededPeriodicNegativeDyadicV1 {
                period_bits: 3,
                fractional_bits: 8,
                minimum_magnitude_mantissa: 1,
                maximum_magnitude_mantissa: 12,
            },
            diagonal: DiagonalConstruction::AbsoluteRowSumPlusMarginV1 {
                margin_mantissa: 16,
            },
        }
    }

    fn template(seed_byte: u8, rhs: RhsSpec) -> ProblemTemplate {
        ProblemTemplate {
            schema: TemplateSchema::V1,
            randomness: TemplateRandomness::LiteralV1 {
                seed: InstanceSeed::from_bytes([seed_byte; 32]),
            },
            matrix: matrix(19),
            rhs,
            requested_outputs: vec![RequestedOutput::SquaredL2ResidualV1],
        }
    }

    fn dia_matrix(dimension: u64) -> MatrixSpec {
        MatrixSpec::SeededSymmetricDiaLaplacianV1 {
            dimension,
            boundary: BoundaryRule::TruncateV1,
            fractional_bits: 8,
            diagonal_shift_mantissa: 16,
            edge_diagonals: vec![
                SymmetricDiaEdge {
                    positive_offset: 1,
                    period_bits: 2,
                    minimum_weight_mantissa: 1,
                    maximum_weight_mantissa: 7,
                },
                SymmetricDiaEdge {
                    positive_offset: 4,
                    period_bits: 1,
                    minimum_weight_mantissa: 2,
                    maximum_weight_mantissa: 9,
                },
            ],
        }
    }

    fn nonsymmetric_matrix(
        dimension: u64,
        maximum_half_bandwidth: u64,
        maximum_nonzeros_per_row: u8,
    ) -> MatrixSpec {
        MatrixSpec::SeededNonsymmetricRowSparseV1 {
            dimension,
            boundary: BoundaryRule::TruncateV1,
            row_pattern_bits: 3,
            maximum_half_bandwidth,
            maximum_nonzeros_per_row,
            fractional_bits: 8,
            minimum_mantissa: -256,
            maximum_mantissa: 256,
        }
    }

    fn projected_nonsymmetric_matrix(
        dimension: u64,
        maximum_half_bandwidth: u64,
        maximum_nonzeros_per_row: u8,
    ) -> MatrixSpec {
        MatrixSpec::SeededNonsymmetricRowSparseV2 {
            dimension,
            boundary: BoundaryRule::TruncateV1,
            row_pattern_bits: 3,
            maximum_half_bandwidth,
            maximum_nonzeros_per_row,
            fractional_bits: 8,
            minimum_mantissa: -256,
            maximum_mantissa: 256,
        }
    }

    fn seeded_rhs() -> RhsSpec {
        RhsSpec::SeededPeriodicDyadicV1 {
            period_bits: 3,
            fractional_bits: 8,
            minimum_mantissa: -64,
            maximum_mantissa: 63,
        }
    }

    fn generated(seed_byte: u8, rhs: RhsSpec) -> GeneratedProblem {
        template(seed_byte, rhs)
            .finalize_literal()
            .unwrap()
            .compile()
            .unwrap()
    }

    fn dia_generated(seed_byte: u8, rhs: RhsSpec) -> GeneratedProblem {
        let mut template = template(seed_byte, rhs);
        template.matrix = dia_matrix(19);
        template.finalize_literal().unwrap().compile().unwrap()
    }

    fn nonsymmetric_generated(seed_byte: u8) -> GeneratedProblem {
        let mut template = template(seed_byte, seeded_rhs());
        template.matrix = nonsymmetric_matrix(37, 5, 7);
        template.finalize_literal().unwrap().compile().unwrap()
    }

    fn projected_nonsymmetric_generated(seed_byte: u8) -> GeneratedProblem {
        let mut template = template(seed_byte, seeded_rhs());
        template.matrix = projected_nonsymmetric_matrix(37, 5, 7);
        template.finalize_literal().unwrap().compile().unwrap()
    }

    #[test]
    fn generation_is_deterministic_and_seed_bound() {
        let lhs = generated(1, RhsSpec::ManufacturedOnesV1);
        let rhs = generated(1, RhsSpec::ManufacturedOnesV1);
        let changed = generated(2, RhsSpec::ManufacturedOnesV1);
        assert_eq!(lhs, rhs);
        assert_ne!(
            lhs.off_diagonal_periodic_mantissas(),
            changed.off_diagonal_periodic_mantissas()
        );
        assert_ne!(lhs.problem_digest(), changed.problem_digest());
    }

    #[test]
    fn rows_are_sorted_symmetric_negative_and_strictly_dominant() {
        let problem = generated(9, RhsSpec::ManufacturedOnesV1);
        for row_index in 0..problem.dimension() {
            let row = problem.row(row_index).unwrap().collect::<Vec<_>>();
            assert!(row.windows(2).all(|pair| pair[0].column < pair[1].column));
            let diagonal = row
                .iter()
                .find(|entry| entry.column == row_index)
                .unwrap()
                .value
                .mantissa();
            let off_sum: i64 = row
                .iter()
                .filter(|entry| entry.column != row_index)
                .map(|entry| {
                    assert!(entry.value.mantissa() < 0);
                    entry.value.mantissa().abs()
                })
                .sum();
            assert_eq!(diagonal - off_sum, 16);
            for entry in &row {
                let transpose = problem
                    .row(entry.column)
                    .unwrap()
                    .find(|candidate| candidate.column == row_index)
                    .unwrap();
                assert_eq!(entry.value, transpose.value);
            }
        }
    }

    #[test]
    fn dia_rows_derive_symmetry_dominance_and_exact_structure_from_edges() {
        let problem = dia_generated(17, RhsSpec::ManufacturedOnesV1);
        let dimension = problem.dimension();
        let expected_nonzeros = dimension + 2 * ((dimension - 1) + (dimension - 4));
        assert_eq!(problem.structural_nonzeros(), expected_nonzeros);
        assert_eq!(
            problem.rows().map(|row| row.len()).sum::<usize>(),
            expected_nonzeros
        );
        for row_index in 0..dimension {
            let row = problem.row(row_index).unwrap().collect::<Vec<_>>();
            assert!(row.windows(2).all(|pair| pair[0].column < pair[1].column));
            let diagonal = row
                .iter()
                .find(|entry| entry.column == row_index)
                .unwrap()
                .value
                .mantissa();
            let off_diagonal_sum = row
                .iter()
                .filter(|entry| entry.column != row_index)
                .map(|entry| {
                    assert!(entry.value.mantissa() < 0);
                    let transpose = problem
                        .row(entry.column)
                        .unwrap()
                        .find(|candidate| candidate.column == row_index)
                        .unwrap();
                    assert_eq!(entry.value, transpose.value);
                    entry.value.mantissa().unsigned_abs()
                })
                .sum::<u64>();
            assert_eq!(u64::try_from(diagonal).unwrap() - off_diagonal_sum, 16);

            let reverse = problem.row(row_index).unwrap().rev().collect::<Vec<_>>();
            assert_eq!(reverse, row.iter().rev().copied().collect::<Vec<_>>());
        }
        let certificate = problem.certificate();
        assert!(certificate.symmetric);
        assert!(certificate.strictly_row_diagonally_dominant);
        assert!(certificate.nonsingular_m_matrix);
        assert_eq!(certificate.maximum_nonzeros_per_row, 5);
    }

    #[test]
    fn nonsymmetric_rows_generate_sorted_bounded_patterns_and_mixed_sign_values() {
        let problem = nonsymmetric_generated(29);
        let matrix = match &problem.matrix {
            CompiledMatrixFamily::NonsymmetricRowSparse(matrix) => matrix,
            _ => unreachable!(),
        };
        for offsets in matrix
            .signed_offsets
            .chunks_exact(matrix.off_diagonals_per_pattern)
        {
            assert!(offsets.windows(2).all(|pair| pair[0] < pair[1]));
            assert!(offsets.iter().all(|offset| *offset != 0));
            assert!(offsets.iter().all(|offset| offset.unsigned_abs() <= 5));
        }

        let mut observed_asymmetry = false;
        let mut observed_positive = false;
        let mut observed_negative = false;
        let mut enumerated_nonzeros = 0_usize;
        for row_index in 0..problem.dimension() {
            let row = problem.row(row_index).unwrap().collect::<Vec<_>>();
            enumerated_nonzeros += row.len();
            assert!(row.len() <= 7);
            assert!(row.windows(2).all(|pair| pair[0].column < pair[1].column));
            assert_eq!(
                row.iter().filter(|entry| entry.column == row_index).count(),
                1
            );
            for entry in &row {
                assert!(entry.column.abs_diff(row_index) <= 5);
                assert_ne!(entry.value.mantissa(), 0);
                assert!((-256..=256).contains(&entry.value.mantissa()));
                assert_eq!(entry.value.fractional_bits(), 8);
                observed_positive |= entry.value.mantissa() > 0;
                observed_negative |= entry.value.mantissa() < 0;
                if entry.column != row_index {
                    let transpose = problem
                        .row(entry.column)
                        .unwrap()
                        .find(|candidate| candidate.column == row_index);
                    observed_asymmetry |=
                        transpose.is_none_or(|candidate| candidate.value != entry.value);
                }
            }
        }
        assert_eq!(enumerated_nonzeros, problem.structural_nonzeros());
        assert!(observed_asymmetry);
        assert!(observed_positive && observed_negative);

        let first = problem
            .row(5)
            .unwrap()
            .map(|entry| {
                (
                    isize::try_from(entry.column).expect("test column fits isize") - 5,
                    entry.value,
                )
            })
            .collect::<Vec<_>>();
        let repeated = problem
            .row(13)
            .unwrap()
            .map(|entry| {
                (
                    isize::try_from(entry.column).expect("test column fits isize") - 13,
                    entry.value,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(first, repeated);

        let certificate = problem.certificate();
        assert_eq!(certificate.maximum_nonzeros_per_row, 7);
        assert_eq!(certificate.maximum_half_bandwidth, 5);
        assert!(!certificate.symmetric);
        assert!(!certificate.strictly_row_diagonally_dominant);
        assert!(!certificate.nonsingular_m_matrix);
    }

    #[test]
    fn projected_rows_cover_row_bits_without_a_shared_short_period() {
        let problem = projected_nonsymmetric_generated(29);
        let matrix = match &problem.matrix {
            CompiledMatrixFamily::ProjectedNonsymmetricRowSparse(matrix) => matrix,
            _ => unreachable!(),
        };
        let row_index_bits = problem.dimension().next_power_of_two().ilog2() as usize;
        assert_eq!(matrix.pattern_bits, 3);
        assert_eq!(matrix.row_width, 7);
        assert!((0..row_index_bits).all(|bit| {
            matrix
                .projection_bits
                .iter()
                .any(|&projected| usize::from(projected) == bit)
        }));
        assert!(
            matrix
                .projection_bits
                .chunks_exact(matrix.pattern_bits)
                .all(
                    |projection| projection.iter().copied().collect::<HashSet<_>>().len()
                        == projection.len()
                )
        );

        let padded_dimension = problem.dimension().next_power_of_two();
        let row_pattern_tuples = (0..padded_dimension)
            .map(|row| {
                (0..matrix.row_width)
                    .map(|slot| matrix.row_pattern(row, slot))
                    .collect::<Vec<_>>()
            })
            .collect::<HashSet<_>>();
        assert_eq!(row_pattern_tuples.len(), padded_dimension);

        let mut enumerated_nonzeros = 0_usize;
        for row_index in 0..problem.dimension() {
            let row = problem.row(row_index).unwrap().collect::<Vec<_>>();
            enumerated_nonzeros += row.len();
            assert!(row.len() <= matrix.row_width);
            assert!(row.windows(2).all(|pair| pair[0].column < pair[1].column));
            assert_eq!(
                row.iter().filter(|entry| entry.column == row_index).count(),
                1
            );
            assert!(row.iter().all(|entry| entry.value.mantissa() != 0));
            assert!(
                row.iter()
                    .all(|entry| entry.column.abs_diff(row_index) <= 5)
            );
            if row_index + 1 < problem.dimension() {
                assert!(row.iter().any(|entry| entry.column == row_index + 1));
            }
            let reverse = problem.row(row_index).unwrap().rev().collect::<Vec<_>>();
            assert_eq!(reverse, row.iter().rev().copied().collect::<Vec<_>>());
        }
        assert_eq!(enumerated_nonzeros, problem.structural_nonzeros());

        let certificate = problem.certificate();
        assert_eq!(certificate.maximum_nonzeros_per_row, 7);
        assert_eq!(certificate.maximum_half_bandwidth, 5);
        assert!(!certificate.symmetric);
        assert!(!certificate.strictly_row_diagonally_dominant);
        assert!(!certificate.nonsingular_m_matrix);
    }

    #[test]
    fn projected_index_counter_matches_complete_enumeration() {
        let projection = [4, 1, 3];
        for limit in 0..=32 {
            for pattern in 0..8 {
                let expected = (0..limit)
                    .filter(|&index| {
                        projection
                            .iter()
                            .enumerate()
                            .all(|(pattern_bit, &row_bit)| {
                                ((index >> row_bit) & 1) == ((pattern >> pattern_bit) & 1)
                            })
                    })
                    .count();
                assert_eq!(
                    projected_index_count(limit, 5, &projection, pattern),
                    expected,
                    "limit={limit}, pattern={pattern}"
                );
            }
        }
    }

    #[test]
    fn projected_offset_buckets_are_ordered_disjoint_and_include_unit_bridge() {
        for half_bandwidth in 1..=8 {
            for slots in 1..=2 * half_bandwidth {
                let buckets = projected_offset_buckets(half_bandwidth, slots).unwrap();
                assert_eq!(buckets.len(), slots);
                assert!(buckets.iter().all(|bucket| bucket.len > 0));
                assert!(
                    buckets
                        .windows(2)
                        .all(|pair| { pair[0].start + pair[0].len <= pair[1].start })
                );
                assert!(buckets.iter().any(|bucket| {
                    bucket.start == u64::try_from(half_bandwidth).unwrap() && bucket.len == 1
                }));
            }
        }
    }

    #[test]
    fn projected_browser_vector_freezes_cross_language_generation() {
        let mut value = template(1, seeded_rhs());
        value.matrix = MatrixSpec::SeededNonsymmetricRowSparseV2 {
            dimension: 8,
            boundary: BoundaryRule::TruncateV1,
            row_pattern_bits: 2,
            maximum_half_bandwidth: 3,
            maximum_nonzeros_per_row: 5,
            fractional_bits: 8,
            minimum_mantissa: -256,
            maximum_mantissa: 256,
        };
        let problem = value.finalize_literal().unwrap().compile().unwrap();
        let signature = problem
            .rows()
            .enumerate()
            .flat_map(|(row, entries)| {
                entries
                    .map(move |entry| format!("{row},{},{}", entry.column, entry.value.mantissa()))
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(
            signature,
            "0,0,-181\n0,1,-88\n0,3,-10\n1,0,202\n1,1,-32\n1,2,-139\n1,4,-10\n2,0,255\n2,1,-10\n2,2,97\n2,3,18\n2,4,168\n3,1,255\n3,2,202\n3,3,172\n3,4,-45\n3,5,168\n4,1,112\n4,3,100\n4,4,-181\n4,5,-88\n4,7,-28\n5,2,112\n5,4,-173\n5,5,-32\n5,6,-139\n6,3,-214\n6,5,100\n6,6,97\n6,7,18\n7,4,-214\n7,6,-173\n7,7,172"
        );
    }

    #[test]
    fn nonsymmetric_diagonal_only_corner_preserves_required_nonzero() {
        let mut template = template(31, seeded_rhs());
        template.matrix = MatrixSpec::SeededNonsymmetricRowSparseV1 {
            dimension: 4,
            boundary: BoundaryRule::TruncateV1,
            row_pattern_bits: 1,
            maximum_half_bandwidth: 0,
            maximum_nonzeros_per_row: 1,
            fractional_bits: 0,
            minimum_mantissa: -1,
            maximum_mantissa: 1,
        };
        let problem = template.finalize_literal().unwrap().compile().unwrap();
        assert_eq!(problem.structural_nonzeros(), 4);
        for row_index in 0..4 {
            let mut row = problem.row(row_index).unwrap();
            assert_eq!(row.len(), 1);
            let diagonal = row.next().unwrap();
            assert_eq!(diagonal.column, row_index);
            assert!(matches!(diagonal.value.mantissa(), -1 | 1));
            assert!(row.next().is_none());
        }
    }

    #[test]
    fn truncating_endpoints_and_structural_nnz_are_exact() {
        let problem = generated(4, RhsSpec::ManufacturedOnesV1);
        assert_eq!(problem.row(0).unwrap().len(), 2);
        assert_eq!(problem.row(problem.dimension() - 1).unwrap().len(), 2);
        assert!(
            problem
                .rows()
                .skip(1)
                .take(problem.dimension() - 2)
                .all(|row| row.len() == 3)
        );
        let enumerated = problem.rows().map(|row| row.len()).sum::<usize>();
        assert_eq!(problem.structural_nonzeros(), 3 * problem.dimension() - 2);
        assert_eq!(enumerated, problem.structural_nonzeros());
        assert!(problem.row(problem.dimension()).is_none());
    }

    #[test]
    fn manufactured_rhs_is_exactly_matrix_times_ones() {
        let problem = generated(5, RhsSpec::ManufacturedOnesV1);
        for row_index in 0..problem.dimension() {
            let row_sum: i64 = problem
                .row(row_index)
                .unwrap()
                .map(|entry| entry.value.mantissa())
                .sum();
            let rhs = problem.rhs(row_index).unwrap();
            assert_eq!(rhs.fractional_bits(), 8);
            assert_eq!(rhs.mantissa(), row_sum);
            assert_eq!(problem.rhs_f64(row_index), Some(rhs.to_f64()));
        }
        assert!(problem.rhs(problem.dimension()).is_none());
    }

    #[test]
    fn seeded_rhs_is_bounded_periodic_and_domain_separated() {
        let rhs = RhsSpec::SeededPeriodicDyadicV1 {
            period_bits: 2,
            fractional_bits: 6,
            minimum_mantissa: -7,
            maximum_mantissa: 11,
        };
        let problem = generated(3, rhs);
        let table = problem.rhs_periodic_mantissas().unwrap();
        assert_eq!(table.len(), 4);
        assert!(table.iter().all(|value| (-7..=11).contains(value)));
        for row in 0..problem.dimension() - table.len() {
            assert_eq!(problem.rhs(row), problem.rhs(row + table.len()));
        }
        assert_ne!(
            table,
            &problem.off_diagonal_periodic_mantissas()[..table.len()]
        );
    }

    #[test]
    fn seeded_rhs_stream_is_independent_of_the_compiled_matrix_family() {
        let rhs = RhsSpec::SeededPeriodicDyadicV1 {
            period_bits: 3,
            fractional_bits: 6,
            minimum_mantissa: -17,
            maximum_mantissa: 19,
        };
        let tridiagonal = generated(23, rhs);
        let dia = dia_generated(23, rhs);
        let mut nonsymmetric_template = template(23, rhs);
        nonsymmetric_template.matrix = nonsymmetric_matrix(19, 5, 7);
        let nonsymmetric = nonsymmetric_template
            .finalize_literal()
            .unwrap()
            .compile()
            .unwrap();
        assert_eq!(
            tridiagonal.rhs_periodic_mantissas(),
            dia.rhs_periodic_mantissas()
        );
        assert_eq!(
            tridiagonal.rhs_periodic_mantissas(),
            nonsymmetric.rhs_periodic_mantissas()
        );
        assert_ne!(
            tridiagonal.off_diagonal_periodic_mantissas(),
            dia.off_diagonal_periodic_mantissas()
        );
    }

    #[test]
    fn derived_context_recomputes_and_validates() {
        let mut template = template(0, RhsSpec::ManufacturedOnesV1);
        template.randomness = TemplateRandomness::ChallengeDerivedV1 {
            derivation: SeedDerivation::Blake3XofV1,
        };
        let problem = template
            .finalize_with_challenge_context(b"signed challenge")
            .unwrap();
        problem
            .verify_challenge_context(b"signed challenge")
            .unwrap();
        assert!(
            problem
                .verify_challenge_context(b"other challenge")
                .is_err()
        );

        let mut tampered = problem.clone();
        tampered.schema = ProblemSchema::V1;
        if let crate::FinalizedRandomness::ChallengeDerivedV1 { seed, .. } =
            &mut tampered.randomness
        {
            *seed = InstanceSeed::from_bytes([99; 32]);
        }
        assert!(matches!(
            tampered.validate(),
            Err(ProblemError::DerivedSeedMismatch)
        ));
    }

    #[test]
    fn sampler_stays_in_range_for_non_power_of_two_bounds() {
        let mut stream = UniformStream::new(InstanceSeed::from_bytes([42; 32]));
        let samples = (0..10_000)
            .map(|_| stream.sample_below(7))
            .collect::<Vec<_>>();
        assert!(samples.iter().all(|sample| *sample < 7));
        assert!((0..7).all(|value| samples.contains(&value)));
    }

    #[test]
    fn nonsymmetric_value_sampler_is_bounded_and_never_stores_zero() {
        let mut stream = UniformStream::new(InstanceSeed::from_bytes([43; 32]));
        for (minimum, maximum) in [(-7, 11), (-7, 0), (0, 11), (-1, -1), (1, 1)] {
            for _ in 0..1_000 {
                let value = sample_nonzero_mantissa(&mut stream, minimum, maximum);
                assert!((minimum..=maximum).contains(&value));
                assert_ne!(value, 0);
            }
        }
    }
}
