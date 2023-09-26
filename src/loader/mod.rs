use std::{ffi::c_void, intrinsics, ops::Add};

use color_eyre::{eyre, Result};
use goblin::pe::{
    header::{COFF_MACHINE_X86, COFF_MACHINE_X86_64},
    relocation::{
        IMAGE_REL_AMD64_ADDR32, IMAGE_REL_AMD64_ADDR32NB, IMAGE_REL_AMD64_ADDR64,
        IMAGE_REL_AMD64_REL32, IMAGE_REL_I386_DIR32, IMAGE_REL_I386_REL32,
    },
    symbol::Symbol,
    Coff,
};
use tracing::{debug, info, warn};
use widestring::WideCString;
use windows::{
    core::{PCSTR, PCWSTR},
    Win32::System::{
        LibraryLoader::{GetProcAddress, LoadLibraryW},
        Memory::{
            VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
            PAGE_EXECUTE_READWRITE, VIRTUAL_ALLOCATION_TYPE,
        },
        SystemServices::MEM_TOP_DOWN,
    },
};

use crate::O;

use self::beacon_api::{beacon_get_output_data, get_function_ptr, INTERNAL_FUNCTION_NAMES};

pub mod beacon_api;
pub mod beacon_pack;

#[derive(Debug)]
struct MappedFunction {
    address: usize,
    name: String,
}

struct MappedFunctions {
    list: [MappedFunction; 128], // Defines the limit of mapped functions, in this case a hard-coded 128.
    len: usize,
}

/// MappedFunctions is a struct that contains a list of mapped functions and the length of the list.
impl MappedFunctions {
    /// new returns a new MappedFunctions struct.
    fn new() -> *mut Self {
        let function = unsafe {
            let allocation = VirtualAlloc(
                None,
                core::mem::size_of::<MappedFunctions>(),
                MEM_COMMIT | MEM_RESERVE | VIRTUAL_ALLOCATION_TYPE(MEM_TOP_DOWN),
                PAGE_EXECUTE_READWRITE,
            );

            debug!("Function allocated at: {:p}", allocation);

            if allocation.is_null() {
                panic!("Failed to allocate function");
            }

            std::ptr::write_bytes(allocation, 0, core::mem::size_of::<MappedFunctions>());
            &mut *(allocation as *mut MappedFunctions)
        };

        function
    }

    /// push pushes a mapped function to the list.
    fn push(&mut self, entry: MappedFunction) {
        self.list[self.len] = entry;
        self.len += 1;
    }
}

impl Drop for MappedFunctions {
    /// drop frees the memory allocated for the MappedFunctions struct.
    fn drop(&mut self) {
        unsafe {
            let functions = self as *mut _ as *mut c_void;
            VirtualFree(functions, 0, MEM_RELEASE);
        }
    }
}

/// CoffLoader is a struct that contains a slice of bytes representing a COFF file and a parsed COFF file.
pub struct Coffee<'a> {
    coff_buffer: &'a [u8],
    coff: Coff<'a>,
}

/// Static variable that contains the mapped functions.
static mut FUNCTION_MAPPING: Option<&mut MappedFunctions> = None;

/// Static variable that contains the index of the .text section.
static mut TEXT_SECTION_INDEX: i32 = 0;

/// Static variable that contains the mapped sections.
static mut SECTION_MAPPING: Vec<usize> = Vec::new();

impl<'a> Coffee<'a> {
    /// Creates a new CoffLoader struct from a slice of bytes representing a COFF file.
    pub fn new(coff_buffer: &'a [u8]) -> Result<Self> {
        let coff = Coff::parse(coff_buffer)?;

        Ok(Self { coff_buffer, coff })
    }

    /// Executes a bof file by allocating memory for the bof and executing it.
    /// The arguments are passed as a pointer to a byte array and the size of the byte array.
    /// The entrypoint name is optional and is used to specify a custom entrypoint name.
    /// The default entrypoint name is go.
    /// The output of the bof is printed to stdout.
    pub fn execute(
        &self,
        arguments: Option<*const u8>,
        argument_size: Option<usize>,
        entrypoint_name: Option<String>,
    ) -> Result<()> {
        // Check if COFF is running on the current architecture
        if self.is_x86()? && cfg!(target_arch = "x86_64") {
            panic!("Cannot run x86 COFF on x86_64 architecture");
        } else if self.is_x64()? && cfg!(target_arch = "x86") {
            panic!("Cannot run x64 COFF on i686 architecture");
        }

        // Allocate memory for the bof
        self.allocate_bof_memory()?;

        // Execute the bof
        self.execute_bof(arguments, argument_size, entrypoint_name)?;

        // Get the output and print it
        let output_data = beacon_get_output_data();


        unsafe {
            if output_data.len() > 0 {
                O = output_data.flush()
            }
            // O = output_data.flush()
        };

        // Print output data
        // if output_data.len() > 0 {
        //     println!("{}", output_data.flush());
        // }

        // Reset the output data
        output_data.reset();

        // Free the memory of all sections
        self.free_bof_memory()?;

        Ok(())
    }

    /// This is a bit too repetitive
    /// Gets the __imp_(_) based on the architecture
    fn get_imp_based_on_architecture(&self) -> Result<&str> {
        match self.coff.header.machine {
            COFF_MACHINE_X86 => Ok("__imp__"),
            COFF_MACHINE_X86_64 => Ok("__imp_"),
            _ => Err(eyre::eyre!("Unsupported architecture")),
        }
    }

    /// Gets the 32-bit architecture based on the COFF machine type.
    pub fn is_x86(&self) -> Result<bool> {
        match self.coff.header.machine {
            COFF_MACHINE_X86 => Ok(true),
            COFF_MACHINE_X86_64 => Ok(false),
            _ => Err(eyre::eyre!("Unsupported architecture")),
        }
    }

    /// Gets the 64-bit architecture based on the COFF machine type.
    pub fn is_x64(&self) -> Result<bool> {
        match self.coff.header.machine {
            COFF_MACHINE_X86 => Ok(false),
            COFF_MACHINE_X86_64 => Ok(true),
            _ => Err(eyre::eyre!("Unsupported architecture")),
        }
    }

    /// Gets the external or local function address from the symbol name and returns the result.
    /// When the symbol name is an internal function, it will return the address of the function
    /// in the beacon_api module.
    /// When the symbol name is an external function, it will return the procedure address of the function
    /// in the specified library after allocating using the mapping list.
    /// apisets can be shown in the symbol name.
    fn get_import_from_symbol(&self, symbol: Symbol) -> Result<usize> {
        let raw_symbol_name = symbol.name(&self.coff.strings)?;
        debug!("Raw symbol name: {}", raw_symbol_name);

        let polished_import_name = raw_symbol_name
            .split(self.get_imp_based_on_architecture()?) // Some Object files will have __imp_ while on 32-bit for some reason!
            .last()
            .unwrap()
            .split("@")
            .next();

        if polished_import_name.is_none() {
            panic!("Failed to get polished import name");
        }

        let mut symbol_address = 0;

        // Check if the symbol is external or internal
        if polished_import_name.unwrap().contains("$") {
            // This is an external symbol
            // Split $ to get the library name and function name
            let mut split_symbol_name = polished_import_name.unwrap().split("$");
            let library_name_dll =
                format!("{}.dll", split_symbol_name.next().unwrap().to_lowercase());

            // If symbol name contains @, remove everything before the @
            let function_name = split_symbol_name.next();
            if function_name.is_some() {
                let function_name = function_name.unwrap().split("@").next().unwrap();

                info!(
                    "Resolving external import: {}!{}",
                    library_name_dll, function_name
                );

                // Get the function address
                let load_library_address = unsafe {
                    LoadLibraryW(PCWSTR(
                        WideCString::from_str(format!("{}\0", library_name_dll))?.as_ptr(),
                    ))?
                };

                // Get the function address
                let procedure_address = unsafe {
                    GetProcAddress(
                        load_library_address,
                        PCSTR(format!("{}\0", function_name).as_ptr()), // Null terminated string lol :D
                    )
                };

                if procedure_address.is_none() {
                    panic!(
                        "Failed to get procedure address: {}",
                        polished_import_name.unwrap()
                    );
                }

                symbol_address = procedure_address.unwrap() as usize;
            }
        } else {
            // This is an internal symbol
            if INTERNAL_FUNCTION_NAMES.contains(&polished_import_name.unwrap()) {
                info!(
                    "Resolving internal import: {}",
                    polished_import_name.unwrap()
                );
                let internal_func_address =
                    get_function_ptr(polished_import_name.unwrap()).unwrap();

                symbol_address = internal_func_address;
            } else {
                warn!("Unknown internal symbol: {}", polished_import_name.unwrap());
            }
        }

        let mapped_func_entry = MappedFunction {
            address: symbol_address,
            name: polished_import_name.unwrap().to_string(),
        };

        if unsafe { FUNCTION_MAPPING.is_none() } {
            unsafe {
                FUNCTION_MAPPING = Some(&mut *MappedFunctions::new());
            }
        }

        // Push the mapped function to the list
        let mapping_list = unsafe { FUNCTION_MAPPING.as_mut().unwrap() };
        mapping_list.push(mapped_func_entry);

        // Return the address of the mapped function
        let allocated_address = &mapping_list.list.as_ref()[mapping_list.len - 1];
        Ok(&allocated_address.address as *const _ as usize)
    }

    /// Allocates all the memory needed for each relocation and section.
    fn allocate_bof_memory(&self) -> Result<()> {
        // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#coff-file-header-object-and-image
        // Note that the Windows loader limits the number of sections to 96.
        if self.coff.header.number_of_sections > 96 {
            panic!("Number of sections is greater than 96!");
        }

        // Iterate through coff_header NumberOfSections
        info!(
            "Parsing through {} sections.",
            self.coff.header.number_of_sections
        );

        // Handle the allocation and copying of the sections we're going to use
        for idx in 0..self.coff.header.number_of_sections {
            let section = &self.coff.sections[idx as usize];
            let section_size = section.size_of_raw_data as usize;

            let section_base = unsafe {
                VirtualAlloc(
                    None,
                    section_size,
                    MEM_COMMIT | MEM_RESERVE | VIRTUAL_ALLOCATION_TYPE(MEM_TOP_DOWN),
                    PAGE_EXECUTE_READWRITE,
                )
            };

            if section_base.is_null() {
                debug!("Memory for section: {} not allocated.", section.name()?);
            }

            if section.name()?.contains("text") {
                unsafe {
                    TEXT_SECTION_INDEX = idx as i32;
                }
            }

            // Push the section base to the section mapping
            unsafe { SECTION_MAPPING.push(section_base as usize) };

            // Copy the sections into the allocated memory if it is initialized otherwise set the memory to 0
            if !(section.pointer_to_raw_data == 0) {
                info!(
                    "Copying memory for section: {}, base: {:#x}, size: {:#x}",
                    section.name()?,
                    section_base as usize,
                    section_size
                );

                unsafe {
                    intrinsics::volatile_copy_nonoverlapping_memory(
                        section_base as *mut u8,
                        self.coff_buffer
                            .as_ptr()
                            .add(section.pointer_to_raw_data as usize)
                            as *const u8,
                        section_size,
                    );
                }
            } else {
                debug!(
                    "Skipping copy for section: {}, base: {:#x}, size: {:#x}",
                    section.name()?,
                    section_base as usize,
                    section_size
                );

                unsafe {
                    intrinsics::volatile_set_memory(section_base as *mut u8, 0, section_size);
                }
            }
        }

        // Handle the relocations
        for (index, section) in self.coff.sections.iter().enumerate() {
            if section.number_of_relocations > 0 {
                info!("Processing relocations for section: {}", section.name()?);

                // Iterate through the number of relocation entries
                for relocation in section.relocations(self.coff_buffer)? {
                    let mut import_address_ptr = 0;
                    match self
                        .coff
                        .symbols
                        .get(relocation.symbol_table_index as usize)
                    {
                        Some((name, symbol)) => {
                            debug!(
                                "Symbol: {} section: {} value: {} storage class: {:#?}",
                                name.unwrap_or_default(),
                                symbol.section_number,
                                symbol.value,
                                symbol.storage_class
                            );

                            if symbol.section_number < 0 {
                                // Section index
                                warn!(
                                    "Unsupported relocation section number: {}",
                                    symbol.section_number
                                );

                                continue;
                            } else if symbol.section_number == 0 {
                                import_address_ptr = self.get_import_from_symbol(symbol)?;
                                debug!(
                                    "Symbol import address ptr: 0x{:X}",
                                    import_address_ptr as usize
                                );
                            }

                            // Get the target section base that is the section mapping with the symbol section number - 1
                            let target_section_base = {
                                if import_address_ptr == 0 {
                                    unsafe { SECTION_MAPPING[(symbol.section_number as usize) - 1] }
                                } else {
                                    0
                                }
                            };

                            debug!("Relocation type: {:#?}", relocation.typ);

                            // Calculate the relocation overwrite address
                            let relocation_overwrite_address = (unsafe { SECTION_MAPPING[index] })
                                + (relocation.virtual_address as usize)
                                - section.virtual_address as usize;

                            // Handle the relocations based on the architecture
                            if self.is_x64()? {
                                match relocation.typ {
                                    // The 64-bit VA of the relocation target.
                                    IMAGE_REL_AMD64_ADDR64 => {
                                        // The absolute address is the target section base + the relocation overwrite address + the symbol value
                                        let absolute_address = {
                                            if import_address_ptr == 0 {
                                                target_section_base
                                                    + unsafe {
                                                        core::ptr::read_unaligned(
                                                            relocation_overwrite_address
                                                                as *const u32,
                                                        )
                                                            as usize
                                                    }
                                                    + symbol.value as usize
                                            } else {
                                                import_address_ptr
                                            }
                                        };

                                        debug!("Absolute address: {:#x}, relocation overwrite address: {:#x}", absolute_address, relocation_overwrite_address);

                                        // Write the absolute address to the relocation overwrite address
                                        unsafe {
                                            core::ptr::write_unaligned(
                                                relocation_overwrite_address as *mut u64,
                                                absolute_address as u64,
                                            );
                                        }
                                    }
                                    // The 32-bit VA of the relocation target.
                                    IMAGE_REL_AMD64_ADDR32 => {
                                        // The absolute address is the target section base + the relocation overwrite address + the symbol value
                                        let absolute_address = {
                                            if import_address_ptr == 0 {
                                                target_section_base
                                                    + unsafe {
                                                        core::ptr::read_unaligned(
                                                            relocation_overwrite_address
                                                                as *const u32,
                                                        )
                                                            as usize
                                                    }
                                                    + symbol.value as usize
                                            } else {
                                                import_address_ptr
                                            }
                                        };

                                        debug!(
                                            "Absolute address 2: {:#x}, overwrite address: {:#x}",
                                            absolute_address, relocation_overwrite_address
                                        );

                                        // Write the absolute address to the relocation overwrite address
                                        unsafe {
                                            core::ptr::write_unaligned(
                                                relocation_overwrite_address as *mut u32,
                                                absolute_address as u32,
                                            );
                                        }
                                    }
                                    // IMAGE_REL_AMD64_ADDR32NB
                                    IMAGE_REL_AMD64_ADDR32NB => {
                                        let offset = unsafe {
                                            core::ptr::read_unaligned(
                                                relocation_overwrite_address as *const u32,
                                            )
                                        };

                                        let rva_address = {
                                            if import_address_ptr == 0 {
                                                ((target_section_base as isize) + offset as isize)
                                                    .checked_sub(
                                                        (relocation_overwrite_address as isize) + 4,
                                                    )
                                                    .unwrap()
                                            } else {
                                                (import_address_ptr as isize)
                                                    .checked_sub(
                                                        (relocation_overwrite_address as isize) + 4,
                                                    )
                                                    .unwrap()
                                            }
                                        };

                                        debug!(
                                            "RVA address: {:#x}, overwrite address: {:#x}",
                                            rva_address, relocation_overwrite_address
                                        );

                                        // Write the relative virtual address to the relocation overwrite address
                                        unsafe {
                                            core::ptr::write_unaligned(
                                                relocation_overwrite_address as *mut u32,
                                                rva_address as u32,
                                            );
                                        }
                                    }
                                    // The 32-bit relative address from the byte following the relocation.
                                    IMAGE_REL_AMD64_REL32 => {
                                        let offset = unsafe {
                                            core::ptr::read_unaligned(
                                                relocation_overwrite_address as *const u32,
                                            )
                                        }
                                            as usize;

                                        let relative_address = {
                                            if import_address_ptr == 0 {
                                                debug!(
                                                    "Relative absolute base address: {:#x}",
                                                    ((target_section_base as isize)
                                                        + (offset as isize)
                                                        + symbol.value as usize as isize)
                                                );

                                                ((target_section_base as isize)
                                                    + (offset as isize)
                                                    + symbol.value as usize as isize)
                                                    .checked_sub(
                                                        (relocation_overwrite_address as isize) + 4,
                                                    )
                                                    .unwrap()
                                            } else {
                                                (import_address_ptr as isize)
                                                    .checked_sub(
                                                        (relocation_overwrite_address as isize) + 4,
                                                    )
                                                    .unwrap()
                                            }
                                        };

                                        if import_address_ptr != 0 {
                                            debug!(
                                                "Import address: {:#x}, overwrite address: {:#x}",
                                                import_address_ptr, relocation_overwrite_address
                                            );
                                        }

                                        debug!(
                                            "Relative address: {:#x}, overwrite address: {:#x}",
                                            relative_address, relocation_overwrite_address
                                        );

                                        // Write the relative address to the relocation overwrite address
                                        unsafe {
                                            core::ptr::write_unaligned(
                                                relocation_overwrite_address as *mut u32,
                                                relative_address as u32,
                                            );
                                        }
                                    }
                                    _ => {
                                        panic!(
                                            "Unsupported relocation type: {:#?}",
                                            relocation.typ
                                        );
                                    }
                                }
                            } else if self.is_x86()? {
                                match relocation.typ {
                                    // The target's 32-bit VA.
                                    IMAGE_REL_I386_DIR32 => {
                                        let absolute_address = {
                                            if import_address_ptr == 0 {
                                                target_section_base
                                                    + unsafe {
                                                        core::ptr::read_unaligned(
                                                            relocation_overwrite_address
                                                                as *const u32,
                                                        )
                                                            as usize
                                                    }
                                                    + symbol.value as usize
                                            } else {
                                                import_address_ptr
                                            }
                                        };

                                        debug!(
                                            "Absolute address: {:#x}, overwrite address: {:#x}",
                                            absolute_address, relocation_overwrite_address
                                        );

                                        // Write the absolute address to the relocation overwrite address
                                        unsafe {
                                            core::ptr::write_unaligned(
                                                relocation_overwrite_address as *mut u32,
                                                absolute_address as u32,
                                            );
                                        }
                                    }
                                    // The 32-bit relative displacement to the target. This supports the x86 relative branch and call instructions.
                                    IMAGE_REL_I386_REL32 => {
                                        let offset = unsafe {
                                            core::ptr::read_unaligned(
                                                relocation_overwrite_address as *const u32,
                                            )
                                        }
                                            as usize;

                                        let relative_address = {
                                            if import_address_ptr == 0 {
                                                debug!(
                                                    "Relative absolute base address: {:#x}",
                                                    ((target_section_base as isize)
                                                        + (offset as isize)
                                                        + symbol.value as usize as isize)
                                                );

                                                ((target_section_base as isize)
                                                    + (offset as isize)
                                                    + symbol.value as usize as isize)
                                                    .checked_sub(
                                                        (relocation_overwrite_address as isize) + 4,
                                                    )
                                                    .unwrap()
                                            } else {
                                                (import_address_ptr as isize)
                                                    .checked_sub(
                                                        (relocation_overwrite_address as isize) + 4,
                                                    )
                                                    .unwrap()
                                            }
                                        };

                                        if import_address_ptr != 0 {
                                            debug!(
                                                "Import address: {:#x}, overwrite address: {:#x}",
                                                import_address_ptr, relocation_overwrite_address
                                            );
                                        }

                                        debug!(
                                            "Relative address: {:#x}, overwrite address: {:#x}",
                                            relative_address, relocation_overwrite_address
                                        );

                                        // Write the relative address to the relocation overwrite address
                                        unsafe {
                                            core::ptr::write_unaligned(
                                                relocation_overwrite_address as *mut u32,
                                                relative_address as u32,
                                            );
                                        }
                                    }
                                    _ => {
                                        panic!(
                                            "Unsupported relocation type: {:#?}",
                                            relocation.typ
                                        );
                                    }
                                }
                            }
                        }
                        None => {
                            warn!("Symbol in relocation is None");
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn execute_bof(
        &self,
        arguments: Option<*const u8>,
        argument_size: Option<usize>,
        entrypoint_name: Option<String>,
    ) -> Result<()> {
        // Check if BeaconDataParse, BeaconDataPtr, BeaconDataInt, BeaconDataShort, BeaconDataLength or BeaconDataExtract is present on the mapped functions
        let data_functions = [
            "BeaconDataParse",
            "BeaconDataPtr",
            "BeaconDataInt",
            "BeaconDataShort",
            "BeaconDataLength",
            "BeaconDataExtract",
        ];

        let mapped_functions_name = unsafe {
            FUNCTION_MAPPING
                .as_mut()
                .unwrap()
                .list
                .iter()
                .map(|x| x.name.as_str().split("$").last().unwrap_or_default())
                .collect::<Vec<&str>>()
        };

        if mapped_functions_name
            .iter()
            .any(|x| data_functions.contains(x))
            && argument_size.unwrap_or(0) <= 4
        {
            warn!("This BOF requires arguments but no arguments were passed! The BOF may crash or may not function properly!");
        }

        // Iterate each symbol to find the entrypoint
        for (_i, name, symbol) in self.coff.symbols.iter() {
            if name.is_none() {
                continue;
            }

            debug!(
                "Passing through symbol: {} section: {} value: {} storage class: {:#?}",
                name.unwrap_or_default(),
                symbol.section_number,
                symbol.value,
                symbol.storage_class
            );

            let entry_name: String = if entrypoint_name.is_some() {
                entrypoint_name.as_ref().unwrap().to_string()
            } else {
                "go".to_string()
            };

            /* _go for 32-bit for whatever reason? */
            if name.unwrap().contains(entry_name.as_str()) {
                let entry_point = unsafe { SECTION_MAPPING[(TEXT_SECTION_INDEX) as usize] }
                    .add(symbol.value as usize);

                // Call entrypoint
                info!("Calling entrypoint: {}:{:#x}", name.unwrap(), entry_point);

                unsafe {
                    std::mem::transmute::<usize, fn(*const u8, usize)>(entry_point)(
                        arguments.unwrap_or(std::ptr::null()),
                        argument_size.unwrap_or(0),
                    )
                };

                // Break after executing so we don't run .pdata or any other section with relocations
                break;
            }
        }

        Ok(())
    }

    /// Iterates through each section and frees the memory allocated for each section using VirtualFree.
    /// This is done to prevent memory leaks.
    fn free_bof_memory(&self) -> Result<()> {
        // Drop mapped functions
        unsafe {
            FUNCTION_MAPPING = None;
        }

        for (idx, _section) in self.coff.sections.iter().enumerate() {
            let section_base = unsafe { SECTION_MAPPING[idx] };

            if section_base == 0 {
                continue;
            }

            unsafe {
                VirtualFree(section_base as *mut c_void, 0, MEM_RELEASE);
            }
        }

        Ok(())
    }
}
