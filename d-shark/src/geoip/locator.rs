use maxminddb::Reader;
use std::net::IpAddr;
use std::path::Path;

#[derive(Debug)]
pub struct GeoIPResult {
    pub country: Option<String>,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
}

pub struct GeoIPLocator {
    reader: Option<Reader<Vec<u8>>>,
}

impl GeoIPLocator {
    pub fn new() -> Self {
        // В реальном приложении здесь должен быть путь к базе GeoIP
        // Например: "GeoLite2-City.mmdb"
        GeoIPLocator {
            reader: None,
        }
    }

    pub fn with_database<P: AsRef<Path>>(path: P) -> Result<Self, maxminddb::MaxMindDBError> {
        let reader = Reader::open_readfile(path)?;
        Ok(GeoIPLocator {
            reader: Some(reader),
        })
    }

    pub fn lookup(&self, ip: &str) -> Option<GeoIPResult> {
        let ip_addr: IpAddr = ip.parse().ok()?;
        self.reader.as_ref().and_then(|reader| {
            match reader.lookup::<maxminddb::geoip2::City>(ip_addr) {
                Ok(city) => {
                    let country = city.country.and_then(|c| c.names).and_then(|names| names.get("en").map(|s| s.to_string()));
                    let city_name = city.city.and_then(|c| c.names).and_then(|names| names.get("en").map(|s| s.to_string()));
                    let location = city.location;
                    
                    Some(GeoIPResult {
                        country,
                        city: city_name,
                        latitude: location.and_then(|loc| loc.latitude),
                        longitude: location.and_then(|loc| loc.longitude),
                    })
                }
                Err(_) => None,
            }
        })
    }

    pub fn is_available(&self) -> bool {
        self.reader.is_some()
    }
}

impl Default for GeoIPLocator {
    fn default() -> Self {
        Self::new()
    }
}