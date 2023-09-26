#![allow(unused_assignments)]

#[cfg(target_os = "windows")]
extern crate winapi;

use std::mem::size_of;
pub use ffi::get_screenshot;


#[derive(Clone, Copy)]
pub struct Pixel {
    pub a: u8,
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

/// An image buffer containing the screenshot.
/// Pixels are stored as [ARGB](https://en.wikipedia.org/wiki/ARGB).
pub struct Screenshot {
    data: Vec<u8>,
    height: usize,
    width: usize,
    row_len: usize,
    // Might be superfluous
    pixel_width: usize,
}

impl Screenshot {
    /// Height of image in pixels.
    #[inline]
    pub fn height(&self) -> usize { self.height }

    /// Width of image in pixels.
    #[inline]
    pub fn width(&self) -> usize { self.width }

    /// Number of bytes in one row of bitmap.
    #[inline]
    pub fn row_len(&self) -> usize { self.row_len }

    /// Width of pixel in bytes.
    #[inline]
    pub fn pixel_width(&self) -> usize { self.pixel_width }

    /// Raw bitmap.
    #[inline]
    pub fn raw_data(&self) -> *const u8 {
        &self.data[0] as *const u8
    }

    /// Raw bitmap.
    #[inline]
    pub unsafe fn raw_data_mut(&mut self) -> *mut u8 {
        &mut self.data[0] as *mut u8
    }

    /// Number of bytes in bitmap
    #[inline]
    pub fn raw_len(&self) -> usize {
        self.data.len() * size_of::<u8>()
    }

    /// Gets pixel at (row, col)
    pub fn get_pixel(&self, row: usize, col: usize) -> Pixel {
        let idx = row * self.row_len() + col * self.pixel_width();
        unsafe {
            //let data = &self.data[0] as *const u8;
            if idx > self.data.len() { panic!("Bounds overflow"); }

            Pixel {
                a: *self.data.get_unchecked(idx + 3),
                r: *self.data.get_unchecked(idx + 2),
                g: *self.data.get_unchecked(idx + 1),
                b: *self.data.get_unchecked(idx),
            }
        }
    }
}

impl AsRef<[u8]> for Screenshot {
    #[inline]
    fn as_ref<'a>(&'a self) -> &'a [u8] {
        self.data.as_slice()
    }
}

pub type ScreenResult = Result<Screenshot, &'static str>;

#[cfg(target_os = "windows")]
mod ffi {
    #![allow(non_snake_case, dead_code)]

    use std::mem::size_of;

    use winapi::um::winuser;
    use winapi::um::wingdi;
    use winapi::shared::windef;
    use winapi::shared::ntdef;
    use winapi::shared::minwindef;

    use crate::screenshot_lib::Screenshot;
    use crate::screenshot_lib::ScreenResult;

    /// Reorder rows in bitmap, last to first.
    /// TODO rewrite functionally
    fn flip_rows(data: Vec<u8>, height: usize, row_len: usize) -> Vec<u8> {
        let mut new_data = Vec::with_capacity(data.len());
        unsafe { new_data.set_len(data.len()) };
        for row_i in 0..height {
            for byte_i in 0..row_len {
                let old_idx = (height - row_i - 1) * row_len + byte_i;
                let new_idx = row_i * row_len + byte_i;
                new_data[new_idx] = data[old_idx];
            }
        }
        new_data
    }


    pub fn get_screenshot(_screen: usize) -> ScreenResult {
        unsafe {
            // Enumerate monitors, getting a handle and DC for requested monitor.
            // loljk, because doing that on Windows is worse than death
            winsafe::SetProcessDPIAware().unwrap();
            let h_wnd_screen = winuser::GetDesktopWindow();
            let h_dc_screen = winuser::GetDC(h_wnd_screen);
            let width = winuser::GetSystemMetrics(winuser::SM_CXSCREEN);
            let height = winuser::GetSystemMetrics(winuser::SM_CYSCREEN);

            // Create a Windows Bitmap, and copy the bits into it
            let h_dc = wingdi::CreateCompatibleDC(h_dc_screen);
            if h_dc.is_null() { return Err("Can't get a Windows display."); }

            let h_bmp = wingdi::CreateCompatibleBitmap(h_dc_screen, width, height);
            if h_bmp.is_null() { return Err("Can't create a Windows buffer"); }

            let res = wingdi::SelectObject(h_dc, h_bmp as windef::HGDIOBJ);
            if res == ntdef::NULL || res == wingdi::HGDI_ERROR {
                return Err("Can't select Windows buffer.");
            }

            let res = wingdi::BitBlt(h_dc, 0, 0, width, height, h_dc_screen, 0, 0, wingdi::SRCCOPY | wingdi::CAPTUREBLT);
            if res == 0 { return Err("Failed to copy screen to Windows buffer"); }

            // Get image info
            let pixel_width: usize = 4; // FIXME

            let mut bmi = wingdi::BITMAPINFO {
                bmiHeader: wingdi::BITMAPINFOHEADER {
                    biSize: size_of::<wingdi::BITMAPINFOHEADER>() as minwindef::DWORD,
                    biWidth: width as ntdef::LONG,
                    biHeight: height as ntdef::LONG,
                    biPlanes: 1,
                    biBitCount: 8 * pixel_width as minwindef::WORD,
                    biCompression: wingdi::BI_RGB,
                    biSizeImage: (width * height * pixel_width as minwindef::INT) as minwindef::DWORD,
                    biXPelsPerMeter: 0,
                    biYPelsPerMeter: 0,
                    biClrUsed: 0,
                    biClrImportant: 0,
                },
                bmiColors: [wingdi::RGBQUAD {
                    rgbBlue: 0,
                    rgbGreen: 0,
                    rgbRed: 0,
                    rgbReserved: 0,
                }],
            };

            // Create a Vec for image
            let size: usize = (width * height) as usize * pixel_width;
            let mut data: Vec<u8> = Vec::with_capacity(size);
            data.set_len(size);

            // copy bits into Vec
            wingdi::GetDIBits(h_dc, h_bmp, 0, height as minwindef::DWORD,
                              &mut data[0] as *mut u8 as minwindef::LPVOID,
                              &mut bmi as wingdi::LPBITMAPINFO,
                              wingdi::DIB_RGB_COLORS);

            // Release native image buffers
            winuser::ReleaseDC(h_wnd_screen, h_dc_screen); // don't need screen anymore
            wingdi::DeleteDC(h_dc);
            wingdi::DeleteObject(h_bmp as windef::HGDIOBJ);

            let data = flip_rows(data, height as usize, width as usize * pixel_width);

            Ok(Screenshot {
                data,
                height: height as usize,
                width: width as usize,
                row_len: width as usize * pixel_width,
                pixel_width,
            })
        }
    }
}