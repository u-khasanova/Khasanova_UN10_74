# File Format Analysis Report

## Analyze File Formats

### Analyze Signatures of ZIP Format

#### Find Local File Header
```hex
50 4B 03 04 - Local File Header
```

#### Find Central Directory Header & End of Central Directory Record
```hex
50 4B 01 02 - Central Directory Header
50 4B 05 06 - End of Central Directory Record
50 4B 07 08 - Multi-part Archive Header
```

### Analyze Signatures of RAR Format

#### Find Local File Header
```hex
52 61 72 21 1A 07 01 00 - RAR Signature
```

### Analyze Signatures of JPEG Format
```hex
FF D8 FF - JPEG Signature
```

### Analyze Signatures of MP3 Format
```hex
49 44 33 - MP3 Signature (ID3 tag)
FF F2 - MPEG Frame Sync (MPEG 2.5 Layer III)
FF F3 - MPEG Frame Sync (MPEG 2 Layer III)
```

## Make YARA Rule

```yara
rule FileFormatDetector {
    meta:
        description = "Detect ZIP, RAR, JPEG, and MP3 files by signatures"
        author = "Security Analyst"
        date = "2024-05-20"
        version = "1.0"

    strings:
        // ZIP signatures
        $zip_local = { 50 4B 03 04 }
        $zip_central = { 50 4B 01 02 }
        $zip_end = { 50 4B 05 06 }
        
        // RAR signatures  
        $rar_sig = { 52 61 72 21 1A 07 01 00 }
        
        // JPEG signatures
        $jpeg_sig = { FF D8 FF }
        
        // MP3 signatures
        $mp3_id3 = "ID3"
        $mp3_sync1 = { FF F2 }
        $mp3_sync2 = { FF F3 }

    condition:
        any of them
}
```

## Testing and Validation

### Create test directory structure:
```bash
mkdir test_files
cd test_files
touch test.zip test.rar test.jpg test.mp3
```

### Run YARA scan:
```powershell
& "C:\Program Files\YARA\yara64.exe" -r .\FileFormatDetector.yar .\test_files\
```

## Takeaway

Ключевые команды для работы: `yara -r правила.яр директория` и `fhx файл` для анализа hex-дампов.
