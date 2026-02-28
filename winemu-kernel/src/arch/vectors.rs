type Backend = super::backend::ArchBackend;

#[inline(always)]
pub fn install_exception_vectors() {
    <Backend as super::contract::VectorsBackend>::install_exception_vectors();
}
