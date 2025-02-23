use std::{num::Wrapping, time::Instant};

struct RngState {
    x: Wrapping<u64>,
    y: Wrapping<u64>,
    z: Wrapping<u64>,
    w: Wrapping<u64>,
    v: Wrapping<u64>,
    d: Wrapping<u64>,
}

impl Default for RngState {
    fn default() -> Self {
        Self {
            x: Wrapping(123_456_789),
            y: Wrapping(362_436_069),
            z: Wrapping(521_288_629),
            w: Wrapping(88_675_123),
            v: Wrapping(5_783_321),
            d: Wrapping(6_615_241),
        }
    }
}

// George Marsaglia, "Xorshift RNGs", page 5
#[must_use]
fn random_u64(state: &mut RngState, rng_seed: u64) -> u64 {
    let t = state.x ^ (state.x >> 2);
    state.x = state.y;
    state.y = state.z;
    state.z = state.w;
    state.w = state.v;
    state.v = (state.v ^ (state.v << 4)) ^ (t ^ (t << 1));
    state.d += rng_seed;
    (state.d + state.v).0
}

fn generate_data(buf: &mut [u8], seed: u64) {
    let mut state = RngState::default();
    let rng_seed = if seed % 2 == 0 { seed + 1 } else { seed };
    buf.chunks_mut(8).for_each(|val| {
        val.clone_from_slice(&random_u64(&mut state, rng_seed).to_le_bytes()[..val.len()]);
    });
}

#[allow(clippy::result_unit_err)]
pub fn fill_random_buffer(buf: &mut [u8], read_bytes: usize, seed: u64) {
    eprintln!("Generating data...");
    let start = Instant::now();
    generate_data(&mut buf[..read_bytes], seed);
    let time = Instant::now().duration_since(start);

    #[allow(clippy::cast_precision_loss)]
    let time_ms = time.as_micros() as f64 / 1000.0;
    eprintln!(
        "Data generated in {time_ms:.3?} ms",
    );
}
