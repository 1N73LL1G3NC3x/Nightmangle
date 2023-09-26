use crate::chromium::dumper::Dumper;
use std::collections::HashMap;
use crate::chromium::dumper::DumperError;
pub type DumperResult<T> = Result<T, DumperError>;


pub fn chrome_main() -> Vec<Dumper> {

    let mut hm = HashMap::new();
    hm.insert("edge", Dumper::new("Edge", "Microsoft"));
    hm.insert("brave", Dumper::new("Brave-Browser", "BraveSoftware"));
    hm.insert("chromium", Dumper::new("", "Chromium"));
    hm.insert("chrome", Dumper::new("Chrome", "Google"));
    let browsers = &mut hm.clone();

    let opt_browsers = browsers.keys().map(|v| v.to_string()).collect::<Vec<_>>();

    let accvec = opt_browsers
        .into_iter()
        .filter_map(|v| browsers.get(v.as_str()).cloned())
        .map(|mut v| v.dump().map(|_| v))
        .filter_map(|v| v.ok())
        .collect::<Vec<_>>();
    accvec
}
