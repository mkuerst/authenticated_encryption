use super::input_gen::fill_random_buffer;

#[derive(Debug)]
struct AlignedSlice {
    data: Box<[u8]>,
    offset: usize,
}

impl AlignedSlice {
    fn new(data: Box<[u8]>, alignment: usize) -> Self {
        let offset = data.as_ptr() as usize % alignment;
        {
            let aligned_buf = {
                let diff = alignment - offset;
                &data[diff..]
            };
            debug_assert!(aligned_buf.as_ptr() as usize % alignment == 0);
        }
        Self { data, offset }
    }
}

impl AsRef<[u8]> for AlignedSlice {
    fn as_ref(&self) -> &[u8] {
        &self.data[self.offset..]
    }
}

impl AsMut<[u8]> for AlignedSlice {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data[self.offset..]
    }
}

#[derive(Debug)]
pub struct Param {
    backup: Box<[u8]>,
    buf0: AlignedSlice,
    buf1: AlignedSlice,
    key: AlignedSlice,
    nonce: AlignedSlice,
    pub input_size: usize,
}

impl Param {
    #[must_use]
    pub fn new(input_size: usize, alignment: usize) -> Param {
        let buffer_size = 2048.max(input_size + input_size / 16 + alignment); // twice the size to allow for padding and hash values
        let backup = vec![0; input_size].into_boxed_slice();
        let buf0 = AlignedSlice::new(vec![0; buffer_size].into_boxed_slice(), alignment);
        let buf1 = AlignedSlice::new(vec![0; buffer_size].into_boxed_slice(), alignment);
        let key = generate_key(alignment);
        let nonce = generate_nonce(alignment);

        let mut param = Self {
            backup,
            buf0,
            buf1,
            key,
            nonce,
            input_size,
        };

        fill_random_buffer(param.input_mut(), input_size, 69420);

        param
            .backup
            .clone_from_slice(&param.buf0.as_ref()[..input_size]);

        param
    }

    #[must_use]
    pub fn get_key(&self) -> &[u8] {
        self.key.as_ref()
    }

    #[must_use]
    pub fn get_nonce(&self) -> &[u8] {
        self.nonce.as_ref()
    }

    #[must_use]
    pub const fn get_backup(&self) -> &[u8] {
        &self.backup
    }

    #[must_use]
    pub fn input(&self) -> &[u8] {
        self.buf0.as_ref()
    }

    #[must_use]
    pub fn input_ptr(&self) -> *const u8 {
        self.input().as_ptr()
    }

    #[must_use]
    pub fn input_mut(&mut self) -> &mut [u8] {
        self.buf0.as_mut()
    }

    #[must_use]
    pub fn output(&self) -> &[u8] {
        self.buf1.as_ref()
    }

    #[must_use]
    pub fn output_mut(&mut self) -> &mut [u8] {
        self.buf1.as_mut()
    }

    #[must_use]
    pub fn output_ptr(&mut self) -> *mut u8 {
        self.output_mut().as_mut_ptr()
    }

    pub fn swap_buffers(&mut self) {
        std::mem::swap(&mut self.buf0, &mut self.buf1);
    }

    pub fn restore_input(&mut self) {
        self.buf0.as_mut()[..self.input_size].clone_from_slice(&self.backup);
    }

    #[must_use]
    pub fn check_correct_output(&self) -> bool {
        let backup: &[u8] = &self.backup;
        backup == &self.output()[..backup.len()]
    }
}

#[must_use]
fn generate_key(alignment: usize) -> AlignedSlice {
    const SIZE: usize = 1024;
    // Create some values for a key and a nonce:
    #[allow(clippy::cast_possible_truncation)]
    let key_values: Box<[u8]> = (0..(SIZE as u64))
        .map(|x| x.wrapping_add(42).wrapping_mul(x).wrapping_mul(x) as u8)
        .collect();
    let buf = vec![0u8; SIZE + alignment].into_boxed_slice();
    let mut key = AlignedSlice::new(buf, alignment);
    key.as_mut()[..SIZE].clone_from_slice(&key_values);

    key
}

#[must_use]
fn generate_nonce(alignment: usize) -> AlignedSlice {
    const SIZE: usize = 1024;
    // Create some values for a key and a nonce:
    #[allow(clippy::cast_possible_truncation)]
    let nonce_values: Box<[u8]> = (0..(SIZE as u64))
        .map(|x| x.wrapping_add(69).wrapping_mul(x).wrapping_mul(x) as u8)
        .collect();

    let buf = vec![0u8; SIZE + alignment].into_boxed_slice();
    let mut nonce = AlignedSlice::new(buf, alignment);
    nonce.as_mut()[..SIZE].clone_from_slice(&nonce_values);

    nonce
}
