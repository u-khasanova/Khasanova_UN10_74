rule FileExtensionDetector {
	meta: 
		description = "Обнаружение файлов форматов RAR, ZIP, MP3, JPEG"
		author = "Хасанова У.Н."
		
	strings: 
		$rar = { 52 61 72 21 1A 07 01 00 }
		$zip = { 50 4B ( 01 02 | 07 08 )}
		$jpeg = { FF D8 FF }
		$mp3 = { ( 49 44 33 | FF ( F2 | F3 ) ) }
	
	condition: 
		$rar or $zip or $jpeg or $mp3  
}