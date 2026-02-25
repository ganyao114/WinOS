/// Guest Physical Address
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Gpa(pub u64);

/// Guest Virtual Address
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Gva(pub u64);

impl Gpa {
    pub fn offset(self, n: u64) -> Self { Gpa(self.0 + n) }
    pub fn align_down(self, align: u64) -> Self { Gpa(self.0 & !(align - 1)) }
    pub fn align_up(self, align: u64) -> Self {
        Gpa((self.0 + align - 1) & !(align - 1))
    }
}

impl Gva {
    pub fn offset(self, n: u64) -> Self { Gva(self.0 + n) }
    pub fn align_down(self, align: u64) -> Self { Gva(self.0 & !(align - 1)) }
    pub fn align_up(self, align: u64) -> Self {
        Gva((self.0 + align - 1) & !(align - 1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gpa_align_down() {
        assert_eq!(Gpa(0x4001).align_down(0x1000), Gpa(0x4000));
        assert_eq!(Gpa(0x4000).align_down(0x1000), Gpa(0x4000));
    }

    #[test]
    fn gpa_align_up() {
        assert_eq!(Gpa(0x4001).align_up(0x1000), Gpa(0x5000));
        assert_eq!(Gpa(0x4000).align_up(0x1000), Gpa(0x4000));
    }
}
