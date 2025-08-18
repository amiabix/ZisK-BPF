use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use anyhow::{Result, anyhow};

// ELF header constants
const ELF_MAGIC: [u8; 4] = [0x7f, 0x45, 0x4c, 0x46]; // \x7fELF
const ELF_CLASS_64: u8 = 2;
const ELF_DATA_LITTLE: u8 = 1;
const ELF_VERSION: u8 = 1;
const ELF_OSABI_SYSV: u8 = 0;
const ELF_TYPE_EXEC: u16 = 2;
const ELF_MACHINE_X86_64: u16 = 0x3e;

// Section header types
const SHT_PROGBITS: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_RELA: u32 = 4;
const SHT_HASH: u32 = 5;
const SHT_DYNAMIC: u32 = 6;
const SHT_NOTE: u32 = 7;
const SHT_NOBITS: u32 = 8;
const SHT_REL: u32 = 9;
const SHT_SHLIB: u32 = 10;
const SHT_DYNSYM: u32 = 11;

// Section flags
const SHF_WRITE: u64 = 0x1;
const SHF_ALLOC: u64 = 0x2;
const SHF_EXECINSTR: u64 = 0x4;

#[derive(Debug)]
pub struct ElfHeader {
    pub magic: [u8; 4],
    pub class: u8,
    pub data: u8,
    pub version: u8,
    pub osabi: u8,
    pub abi_version: u8,
    pub padding: [u8; 7],
    pub file_type: u16,
    pub machine: u16,
    pub version_elf: u32,
    pub entry_point: u64,
    pub program_header_offset: u64,
    pub section_header_offset: u64,
    pub flags: u32,
    pub header_size: u16,
    pub program_header_entry_size: u16,
    pub program_header_count: u16,
    pub section_header_entry_size: u16,
    pub section_header_count: u16,
    pub section_name_string_table_index: u16,
}

#[derive(Debug)]
pub struct SectionHeader {
    pub name_index: u32,
    pub section_type: u32,
    pub flags: u64,
    pub virtual_address: u64,
    pub file_offset: u64,
    pub size: u64,
    pub link: u32,
    pub info: u32,
    pub alignment: u64,
}

#[derive(Debug)]
pub struct BpfSection {
    pub name: String,
    pub offset: u64,
    pub size: u64,
    pub data: Vec<u8>,
}

pub struct ElfParser {
    file: File,
    header: ElfHeader,
    section_headers: Vec<SectionHeader>,
}

impl ElfParser {
    pub fn new(file_path: &str) -> Result<Self> {
        let mut file = File::open(file_path)?;
        
        // Read and validate ELF header
        let header = Self::read_elf_header(&mut file)?;
        
        // Read section headers
        let section_headers = Self::read_section_headers(&mut file, &header)?;
        
        Ok(Self {
            file,
            header,
            section_headers,
        })
    }
    
    fn read_elf_header(file: &mut File) -> Result<ElfHeader> {
        file.seek(SeekFrom::Start(0))?;
        
        let mut buffer = [0u8; 64];
        file.read_exact(&mut buffer)?;
        
        // Validate magic number
        if buffer[0..4] != ELF_MAGIC {
            return Err(anyhow!("Invalid ELF magic number"));
        }
        
        // Parse header fields
        let header = ElfHeader {
            magic: [buffer[0], buffer[1], buffer[2], buffer[3]],
            class: buffer[4],
            data: buffer[5],
            version: buffer[6],
            osabi: buffer[7],
            abi_version: buffer[8],
            padding: [buffer[9], buffer[10], buffer[11], buffer[12], buffer[13], buffer[14], buffer[15]],
            file_type: u16::from_le_bytes([buffer[16], buffer[17]]),
            machine: u16::from_le_bytes([buffer[18], buffer[19]]),
            version_elf: u32::from_le_bytes([buffer[20], buffer[21], buffer[22], buffer[23]]),
            entry_point: u64::from_le_bytes([buffer[24], buffer[25], buffer[26], buffer[27], buffer[28], buffer[29], buffer[30], buffer[31]]),
            program_header_offset: u64::from_le_bytes([buffer[32], buffer[33], buffer[34], buffer[35], buffer[36], buffer[37], buffer[38], buffer[39]]),
            section_header_offset: u64::from_le_bytes([buffer[40], buffer[41], buffer[42], buffer[43], buffer[44], buffer[45], buffer[46], buffer[47]]),
            flags: u32::from_le_bytes([buffer[48], buffer[49], buffer[50], buffer[51]]),
            header_size: u16::from_le_bytes([buffer[52], buffer[53]]),
            program_header_entry_size: u16::from_le_bytes([buffer[54], buffer[55]]),
            program_header_count: u16::from_le_bytes([buffer[56], buffer[57]]),
            section_header_entry_size: u16::from_le_bytes([buffer[58], buffer[59]]),
            section_header_count: u16::from_le_bytes([buffer[60], buffer[61]]),
            section_name_string_table_index: u16::from_le_bytes([buffer[62], buffer[63]]),
        };
        
        // Validate header
        if header.class != ELF_CLASS_64 {
            return Err(anyhow!("Only 64-bit ELF files are supported"));
        }
        
        if header.data != ELF_DATA_LITTLE {
            return Err(anyhow!("Only little-endian ELF files are supported"));
        }
        
        Ok(header)
    }
    
    fn read_section_headers(file: &mut File, header: &ElfHeader) -> Result<Vec<SectionHeader>> {
        let mut section_headers = Vec::new();
        
        file.seek(SeekFrom::Start(header.section_header_offset))?;
        
        for _ in 0..header.section_header_count {
            let mut buffer = [0u8; 64];
            file.read_exact(&mut buffer)?;
            
            let section_header = SectionHeader {
                name_index: u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]),
                section_type: u32::from_le_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]),
                flags: u64::from_le_bytes([buffer[8], buffer[9], buffer[10], buffer[11], buffer[12], buffer[13], buffer[14], buffer[15]]),
                virtual_address: u64::from_le_bytes([buffer[16], buffer[17], buffer[18], buffer[19], buffer[20], buffer[21], buffer[22], buffer[23]]),
                file_offset: u64::from_le_bytes([buffer[24], buffer[25], buffer[26], buffer[27], buffer[28], buffer[29], buffer[30], buffer[31]]),
                size: u64::from_le_bytes([buffer[32], buffer[33], buffer[34], buffer[35], buffer[36], buffer[37], buffer[38], buffer[39]]),
                link: u32::from_le_bytes([buffer[40], buffer[41], buffer[42], buffer[43]]),
                info: u32::from_le_bytes([buffer[44], buffer[45], buffer[46], buffer[47]]),
                alignment: u64::from_le_bytes([buffer[48], buffer[49], buffer[50], buffer[51], buffer[52], buffer[53], buffer[54], buffer[55]]),
            };
            
            section_headers.push(section_header);
        }
        
        Ok(section_headers)
    }
    
    /// Extract BPF bytecode from the .text section
    pub fn extract_bpf_bytecode(&mut self) -> Result<Vec<u8>> {
        // Find the .text section (executable code)
        let text_section = self.section_headers.iter()
            .find(|s| s.section_type == SHT_PROGBITS && (s.flags & SHF_EXECINSTR) != 0)
            .ok_or_else(|| anyhow!("No executable .text section found"))?;
        
        println!("[ELF] Found .text section: offset=0x{:x}, size=0x{:x}", 
                text_section.file_offset, text_section.size);
        
        // Read the BPF bytecode
        self.file.seek(SeekFrom::Start(text_section.file_offset))?;
        
        let mut bpf_data = vec![0u8; text_section.size as usize];
        self.file.read_exact(&mut bpf_data)?;
        
        println!("[ELF] Extracted {} bytes of BPF bytecode", bpf_data.len());
        
        // Show first few instructions for verification
        if bpf_data.len() >= 32 {
            println!("[ELF] First 32 bytes: {:02x?}", &bpf_data[0..32]);
        }
        
        Ok(bpf_data)
    }
    
    /// Get section information for debugging
    pub fn list_sections(&self) -> Vec<BpfSection> {
        let mut sections = Vec::new();
        
        for (i, header) in self.section_headers.iter().enumerate() {
            let section_name = match header.section_type {
                SHT_PROGBITS => {
                    if (header.flags & SHF_EXECINSTR) != 0 {
                        ".text (executable)".to_string()
                    } else {
                        ".data".to_string()
                    }
                },
                SHT_STRTAB => ".strtab".to_string(),
                SHT_SYMTAB => ".symtab".to_string(),
                SHT_DYNSYM => ".dynsym".to_string(),
                SHT_RELA => ".rela".to_string(),
                SHT_DYNAMIC => ".dynamic".to_string(),
                _ => format!("Section {}", i),
            };
            
            sections.push(BpfSection {
                name: section_name,
                offset: header.file_offset,
                size: header.size,
                data: Vec::new(), // We don't load all data by default
            });
        }
        
        sections
    }
    
    /// Validate that this is a valid BPF ELF file
    pub fn validate_bpf_elf(&self) -> Result<()> {
        // Check if it's a shared object (typical for BPF programs)
        if self.header.file_type != 3 { // ET_DYN
            println!("[ELF] Warning: File type is not shared object (ET_DYN)");
        }
        
        // Check if it has executable sections
        let has_executable = self.section_headers.iter()
            .any(|s| s.section_type == SHT_PROGBITS && (s.flags & SHF_EXECINSTR) != 0);
        
        if !has_executable {
            return Err(anyhow!("No executable sections found - not a valid BPF program"));
        }
        
        println!("[ELF] Valid BPF ELF file detected");
        Ok(())
    }
}

/// Convenience function to extract BPF bytecode from a .so file
pub fn extract_bpf_from_so(file_path: &str) -> Result<Vec<u8>> {
    let mut parser = ElfParser::new(file_path)?;
    
    // Validate the ELF file
    parser.validate_bpf_elf()?;
    
    // List sections for debugging
    let sections = parser.list_sections();
    println!("[ELF] File contains {} sections:", sections.len());
    for section in sections {
        println!("  {}: offset=0x{:x}, size=0x{:x}", 
                section.name, section.offset, section.size);
    }
    
    // Extract the BPF bytecode
    let bpf_bytecode = parser.extract_bpf_bytecode()?;
    
    Ok(bpf_bytecode)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_elf_parsing() {
        // This test would require a test ELF file
        // For now, just test that the module compiles
        assert!(true);
    }
}
