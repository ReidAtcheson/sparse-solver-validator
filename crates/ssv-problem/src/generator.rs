use std::iter::FusedIterator;

use blake3::OutputReader;

use crate::{
    BoundaryRule, Dyadic, FinalizedProblem, InstanceSeed, MatrixSpec, ProblemDigest, ProblemError,
    RhsSpec, derive_subseed,
};

const MATRIX_VALUES_LABEL: &str = "matrix/seeded-symmetric-tridiagonal-v1/off-diagonal-values";
const DIA_MATRIX_VALUES_LABEL: &str = "matrix/seeded-symmetric-dia-laplacian-v1/edge-values";
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
/// the finalized problem.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GeneratorCertificate {
    pub dimension: usize,
    pub structural_nonzeros: usize,
    pub maximum_nonzeros_per_row: u8,
    /// Family-defined periodic pattern terms used by one public matrix evaluation.
    ///
    /// This is the table period for the legacy tridiagonal family and the sum
    /// of active per-offset patterns for the DIA family.
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

/// A validated, compiled problem backed only by bounded periodic tables.
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

#[derive(Clone, Copy, Debug)]
struct MatrixSeed(InstanceSeed);

#[derive(Clone, Copy, Debug)]
struct RhsSeed(InstanceSeed);

#[derive(Clone, Copy, Debug)]
struct MatrixFacts {
    dimension: usize,
    structural_nonzeros: usize,
    maximum_nonzeros_per_row: u8,
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

impl Iterator for MatrixRow<'_> {
    type Item = MatrixEntry;

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.inner {
            MatrixRowInner::Tridiagonal(row) => row.next(),
            MatrixRowInner::SymmetricDiaLaplacian(row) => row.next(),
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
        }
    }
}

impl ExactSizeIterator for MatrixRow<'_> {
    fn len(&self) -> usize {
        match &self.inner {
            MatrixRowInner::Tridiagonal(row) => row.len(),
            MatrixRowInner::SymmetricDiaLaplacian(row) => row.len(),
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

    /// Flat periodic matrix values in compiled-family order.
    ///
    /// The legacy tridiagonal has one table. DIA families concatenate one
    /// table per increasing positive-offset descriptor.
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

impl CompiledMatrixFamily {
    pub(crate) fn dimension(&self) -> usize {
        match self {
            Self::Tridiagonal(matrix) => matrix.dimension,
            Self::SymmetricDiaLaplacian(matrix) => matrix.dimension,
        }
    }

    fn row(&self, row: usize) -> MatrixRow<'_> {
        match self {
            Self::Tridiagonal(matrix) => MatrixRow::tridiagonal(matrix, row),
            Self::SymmetricDiaLaplacian(matrix) => MatrixRow::dia(matrix, row),
        }
    }

    pub(crate) const fn evaluator_version(&self) -> u16 {
        match self {
            Self::Tridiagonal(_) => 1,
            Self::SymmetricDiaLaplacian(_) => 2,
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
        }
    }

    fn off_diagonal_mantissas(&self) -> &[i64] {
        match self {
            Self::Tridiagonal(matrix) => &matrix.off_diagonal_mantissas,
            Self::SymmetricDiaLaplacian(matrix) => &matrix.off_diagonal_mantissas,
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
    }
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
        assert_eq!(
            tridiagonal.rhs_periodic_mantissas(),
            dia.rhs_periodic_mantissas()
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
}
