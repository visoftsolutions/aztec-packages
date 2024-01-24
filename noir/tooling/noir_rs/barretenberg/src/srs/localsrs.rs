use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use super::Srs;

#[derive(Debug)]
pub struct LocalSrs {
    pub g1_data: Option<Vec<u8>>,
    pub g2_data: Option<Vec<u8>>,
    pub num_points: Option<u32>,
    pub srs_path: String,
}

impl LocalSrs {
    /// Creates a new LocalSrs instance for loading the required SRS data from a local transcript file.
    ///
    /// # Arguments
    /// * `srs_path` - Local file path of SRS transcript.
    pub fn new(srs_path: &str) -> Self {
        LocalSrs {
            num_points: None,
            g1_data: None,
            g2_data: None,
            srs_path: srs_path.to_string(),
        }
    }

    /// Returns the G1 data from a local SRS transcript file based on the specified number of points.
    ///
    /// # Arguments
    /// * `num_points` - Number of points required for G1 data.
    ///
    /// # Returns
    /// * `Vec<u8>` - A byte vector containing the G1 data.
    fn get_g1_data(&self, num_points: u32) -> Vec<u8> {
        const G1_START: u64 = 28;
        let g1_end: u64 = G1_START + num_points as u64 * 64 - 1;

        let mut file = File::open(self.srs_path.clone()).unwrap();
        file.seek(SeekFrom::Start(G1_START)).unwrap();

        let mut buffer = Vec::new();
        let read_length = (g1_end - G1_START + 1) as usize;
        buffer.resize(read_length, 0);
        file.read_exact(&mut buffer).unwrap();

        buffer[..].to_vec()
    }

    /// Returns the G2 data from a local SRS transcript file.
    ///
    /// # Returns
    /// * `Vec<u8>` - A byte vector containing the G2 data.
    fn get_g2_data(&self) -> Vec<u8> {
        const G2_START: u64 = 28 + 5040001 * 64;
        const G2_END: u64 = G2_START + 128 - 1;

        let mut file = File::open(self.srs_path.clone()).unwrap();
        file.seek(SeekFrom::Start(G2_START)).unwrap();

        let mut buffer = Vec::new();
        let read_length = (G2_END - G2_START + 1) as usize;
        buffer.resize(read_length, 0);
        file.read_exact(&mut buffer).unwrap();

        buffer[..].to_vec()
    }
}

impl Srs for LocalSrs {
    /// Loads the required SRS data into memory.
    ///
    /// # Arguments
    /// * `num_points` - Number of points required for G1 data.
    fn load_data(&mut self, num_points: u32) {
        self.num_points = Some(num_points);
        self.g1_data = Some(self.get_g1_data(num_points));
        self.g2_data = Some(self.get_g2_data());
    }

    fn g1_data(&self) -> &Vec<u8> {
        &self.g1_data.as_ref().unwrap()
    }

    fn g2_data(&self) -> &Vec<u8> {
        &self.g2_data.as_ref().unwrap()
    }

    fn num_points(&self) -> u32 {
        self.num_points.unwrap()
    }
}
