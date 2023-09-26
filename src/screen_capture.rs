use std::io::Cursor;
use image::{Bgr, DynamicImage, ImageFormat};
use crate::screenshot_lib::{get_screenshot};

pub fn save_screenshot() -> Cursor<Vec<u8>> {
    let s = get_screenshot(0).unwrap();
    let mut buffer = DynamicImage::new_bgr8(s.width() as u32, s.height() as u32).to_bgr8();

    let data = s.raw_data();
    let mut idx: isize = 0;
    let row_len = s.row_len() as isize;
    let pixel_width = s.pixel_width() as u32;
    for i in 0..(s.width() - 1) as u32 {
        idx = (i * pixel_width) as isize;
        for j in 0..(s.height() - 1) as u32 {
            unsafe {
                buffer.put_pixel(i, j, Bgr::from([
                    *data.offset(idx),
                    *data.offset(idx + 1),
                    *data.offset(idx + 2)
                ]
                ));
            }
            idx += row_len;
        }
    }
    let mut c = Cursor::new(Vec::<u8>::new());
    let writer = DynamicImage::ImageBgr8(buffer);
    let _ = writer.write_to(&mut c, ImageFormat::Jpeg);
    c
}
