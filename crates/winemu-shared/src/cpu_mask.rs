const CPU_MASK_WORD_BITS: usize = u64::BITS as usize;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CpuMask<const WORDS: usize> {
    words: [u64; WORDS],
}

impl<const WORDS: usize> Default for CpuMask<WORDS> {
    fn default() -> Self {
        Self::empty()
    }
}

impl<const WORDS: usize> CpuMask<WORDS> {
    pub const fn empty() -> Self {
        Self { words: [0; WORDS] }
    }

    pub fn from_cpu(cpu: usize) -> Self {
        let mut mask = Self::empty();
        mask.insert(cpu);
        mask
    }

    pub fn from_low_u64(raw: u64) -> Self {
        let mut mask = Self::empty();
        if WORDS != 0 {
            mask.words[0] = raw;
        }
        mask
    }

    pub fn prefix(count: usize) -> Self {
        let mut mask = Self::empty();
        for cpu in 0..count.min(WORDS * CPU_MASK_WORD_BITS) {
            mask.insert(cpu);
        }
        mask
    }

    pub fn to_low_u64(self) -> u64 {
        if WORDS == 0 { 0 } else { self.words[0] }
    }

    #[inline]
    pub fn insert(&mut self, cpu: usize) {
        if cpu >= WORDS * CPU_MASK_WORD_BITS {
            return;
        }
        let word = cpu / CPU_MASK_WORD_BITS;
        let bit = cpu % CPU_MASK_WORD_BITS;
        self.words[word] |= 1u64 << bit;
    }

    #[inline]
    pub fn remove(&mut self, cpu: usize) {
        if cpu >= WORDS * CPU_MASK_WORD_BITS {
            return;
        }
        let word = cpu / CPU_MASK_WORD_BITS;
        let bit = cpu % CPU_MASK_WORD_BITS;
        self.words[word] &= !(1u64 << bit);
    }

    #[inline]
    pub fn contains(&self, cpu: usize) -> bool {
        if cpu >= WORDS * CPU_MASK_WORD_BITS {
            return false;
        }
        let word = cpu / CPU_MASK_WORD_BITS;
        let bit = cpu % CPU_MASK_WORD_BITS;
        (self.words[word] & (1u64 << bit)) != 0
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.words.iter().all(|word| *word == 0)
    }

    #[inline]
    pub fn count(self) -> u32 {
        self.words.iter().map(|word| word.count_ones()).sum()
    }

    pub fn first(self) -> Option<usize> {
        self.iter_set().next()
    }

    pub fn intersection(self, other: Self) -> Self {
        let mut mask = Self::empty();
        for i in 0..WORDS {
            mask.words[i] = self.words[i] & other.words[i];
        }
        mask
    }

    pub fn union(self, other: Self) -> Self {
        let mut mask = Self::empty();
        for i in 0..WORDS {
            mask.words[i] = self.words[i] | other.words[i];
        }
        mask
    }

    pub fn difference(self, other: Self) -> Self {
        let mut mask = Self::empty();
        for i in 0..WORDS {
            mask.words[i] = self.words[i] & !other.words[i];
        }
        mask
    }

    pub fn intersects(self, other: Self) -> bool {
        !self.intersection(other).is_empty()
    }

    pub fn iter_set(self) -> CpuMaskIter<WORDS> {
        CpuMaskIter {
            mask: self,
            next_cpu: 0,
        }
    }
}

pub struct CpuMaskIter<const WORDS: usize> {
    mask: CpuMask<WORDS>,
    next_cpu: usize,
}

impl<const WORDS: usize> Iterator for CpuMaskIter<WORDS> {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        let max_cpus = WORDS * CPU_MASK_WORD_BITS;
        while self.next_cpu < max_cpus {
            let cpu = self.next_cpu;
            self.next_cpu += 1;
            if self.mask.contains(cpu) {
                return Some(cpu);
            }
        }
        None
    }
}
