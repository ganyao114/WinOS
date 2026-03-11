#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
#[repr(transparent)]
pub struct PhysAddr(u64);

impl PhysAddr {
    #[inline(always)]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    #[inline(always)]
    pub const fn get(self) -> u64 {
        self.0
    }

    #[inline(always)]
    pub const fn is_null(self) -> bool {
        self.0 == 0
    }

    #[inline(always)]
    pub fn checked_add(self, offset: u64) -> Option<Self> {
        self.0.checked_add(offset).map(Self)
    }

    #[inline(always)]
    pub const fn page_base(self, page_size: u64) -> Self {
        Self(self.0 & !(page_size - 1))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(transparent)]
pub struct KernelVa(u64);

impl KernelVa {
    #[inline(always)]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    #[inline(always)]
    pub const fn get(self) -> u64 {
        self.0
    }

    #[inline(always)]
    pub const fn is_null(self) -> bool {
        self.0 == 0
    }

    #[inline(always)]
    pub fn checked_add(self, offset: u64) -> Option<Self> {
        self.0.checked_add(offset).map(Self)
    }

    #[inline(always)]
    pub const fn as_ptr<T>(self) -> *const T {
        self.0 as *const T
    }

    #[inline(always)]
    pub const fn as_mut_ptr<T>(self) -> *mut T {
        self.0 as *mut T
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(transparent)]
pub struct UserVa(u64);

impl UserVa {
    #[inline(always)]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    #[inline(always)]
    pub const fn get(self) -> u64 {
        self.0
    }

    #[inline(always)]
    pub const fn is_null(self) -> bool {
        self.0 == 0
    }

    #[inline(always)]
    pub fn checked_add(self, offset: u64) -> Option<Self> {
        self.0.checked_add(offset).map(Self)
    }

    #[inline(always)]
    pub const fn as_ptr<T>(self) -> *const T {
        self.0 as *const T
    }

    #[inline(always)]
    pub const fn as_mut_ptr<T>(self) -> *mut T {
        self.0 as *mut T
    }
}
