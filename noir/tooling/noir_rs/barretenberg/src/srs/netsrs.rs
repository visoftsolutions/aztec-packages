use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, RANGE};

use super::Srs;

#[derive(Debug)]
pub struct NetSrs {
    pub g1_data: Option<Vec<u8>>,
    pub g2_data: Option<Vec<u8>>,
    pub num_points: Option<u32>,
    pub srs_url: String,
}

impl NetSrs {
    /// Creates a new NetSrs instance for remotely downloading the required SRS data from a URL.
    ///
    /// # Arguments
    /// * `srs_url` - URL to SRS transcript file.
    pub fn new(srs_url: &str) -> Self {
        NetSrs {
            num_points: None,
            g1_data: None,
            g2_data: None,
            srs_url: srs_url.to_string(),
        }
    }

    /// Downloads the G1 data from a URL based on the specified number of points.
    ///
    /// # Arguments
    /// * `num_points` - Number of points required for G1 data.
    ///
    /// # Returns
    /// * `Vec<u8>` - A byte vector containing the G1 data.
    fn get_g1_data(&self, num_points: u32) -> Vec<u8> {
        const G1_START: u32 = 28;
        let g1_end: u32 = G1_START + num_points * 64 - 1;

        let mut headers = HeaderMap::new();
        headers.insert(RANGE, format!("bytes={}-{}", G1_START, g1_end).parse().unwrap());

        let response = Client::new()
            .get(self.srs_url.clone())
            .headers(headers)
            .send()
            .unwrap();
        response.bytes().unwrap().to_vec()
    }

    /// Downloads the G2 data from a URL.
    ///
    /// # Returns
    /// * `Vec<u8>` - A byte vector containing the G2 data.
    fn get_g2_data(&self) -> Vec<u8> {
        const G2_START: usize = 28 + 5040001 * 64;
        const G2_END: usize = G2_START + 128 - 1;

        let mut headers = HeaderMap::new();
        headers.insert(RANGE, format!("bytes={}-{}", G2_START, G2_END).parse().unwrap());

        let response = Client::new()
            .get(self.srs_url.clone())
            .headers(headers)
            .send()
            .unwrap();
        response.bytes().unwrap().to_vec()
    }
}

impl Srs for NetSrs {
    /// Downloads and loads the required SRS data into memory.
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
