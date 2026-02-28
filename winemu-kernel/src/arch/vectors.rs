#[inline(always)]
pub fn install_exception_vectors() {
    super::backend::vectors::install_exception_vectors();
}
