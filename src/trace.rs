use pyo3::prelude::*;

#[repr(C)]
#[derive(Clone, Copy)]
struct TraceRecord { addr: u64, size: u32, _pad: u32 }

#[pyclass]
pub struct TraceRecorder {
    buffer: Vec<TraceRecord>,
    capacity: usize,
    count: usize,
    head: usize,
}

#[pymethods]
impl TraceRecorder {
    #[new]
    pub fn new(capacity: usize) -> Self {
        TraceRecorder {
            buffer: vec![TraceRecord { addr: 0, size: 0, _pad: 0 }; capacity],
            capacity, count: 0, head: 0,
        }
    }

    pub fn record(&mut self, addr: u64, size: u32) {
        self.buffer[self.head] = TraceRecord { addr, size, _pad: 0 };
        self.head = (self.head + 1) % self.capacity;
        self.count += 1;
    }

    pub fn drain(&mut self) -> Vec<(u64, u32)> {
        let n = self.count.min(self.capacity);
        let result: Vec<(u64, u32)> = (0..n).map(|i| {
            let idx = if self.count <= self.capacity { i } else { (self.head + i) % self.capacity };
            let r = self.buffer[idx]; (r.addr, r.size)
        }).collect();
        self.count = 0; self.head = 0; result
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize { self.count.min(self.capacity) }
}
