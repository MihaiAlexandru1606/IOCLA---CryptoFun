extern puts
extern printf

section .data
    filename: db "./input.dat",0
    inputlen: dd 2263
    fmtstr: db "Key: %d",0xa,0

section .text
global main

;------------------------------------------------------------------------------
; functia strlen dermina lungime uni sir primit ca parametrun
; lungimea string-ului este returnata in eax
; pentru determinarea lungimi se foloseste scasb
;------------------------------------------------------------------------------
strlen:
    push    ebp
    mov     ebp, esp

    push    ecx ; salvarea informatie din ecx   
    xor     eax, eax
    cld
    mov     al, 0
    mov     edi, dword [ebp + 8]

    cld
    repnz scasb
     
    ; calculare lungimi sirului de caractere   
    mov     eax, edi
    sub     eax, dword [ebp + 8]
    dec     eax

    ;recupara informatie din ecx
    pop     ecx
    leave
    ret


;------------------------------------------------------------------------------
; functia xor_strings realizea xor byte to byte intre cele doua siruri 
; rezultatul xor-ului este "salvat" in primul string
; pentru acesta in ecx, edx se afla adresa stringurilor, iar in bl, al este 
; mutat cate un caracter pana cand se intalneste \0
;------------------------------------------------------------------------------
xor_strings:
    push    ebp
    mov     ebp, esp
    
    ;salvarea registrilor folositi
    push    eax
    push    ebx
    push    ecx
    push    edx
    
    mov     ecx, [ebp + 8]  ; string1.1
    mov     edx, [ebp + 12] ; string1.2
    
repeat_is_not_zero:
    mov     bl, byte [ecx]
    test    bl, bl
    jz      finish_xor_strings
    mov     al, byte [edx]
    xor     bl, al
    mov     byte [ecx], bl ; scriere mesajului decriptat
    inc     ecx ; deplasare prin string1.1
    inc     edx ; deplasare prin string1.2
    jmp     repeat_is_not_zero
    
finish_xor_strings:
    ; recuparea informatilor din registre
    pop     edx
    pop     ecx
    pop     ebx
    pop     eax
    
    leave
    ret


;------------------------------------------------------------------------------
; functia xor_strings realizea decrpitarea stringului2
; pentru decripatre se foloseste "algoritmul": xor intre caracterul curent
;   si caracterul anterior nemodificat
; pentru acesta in bl se afla caracterul care urmeaza sa fie decripat si in 
;   registrul bh se afla caracterul anterior nemodificat
;------------------------------------------------------------------------------
rolling_xor:
    push    ebp
    mov     ebp, esp
    
    ; salvare registrior folositi
    push    eax
    push    ebx
    
    mov     eax, dword [ebp + 8]
    xor     ebx, ebx
    
repeat_rolling_xor:
    mov     bl, byte [eax] ; caracterul curent
    test    bl, bl ; testarea daca nu este \0
    jz      finish_rolling_xor
    xor     bl, bh
    mov     bh, byte [eax] ; caracterul anterior nemodificat
    mov     byte [eax], bl
    inc     eax
    jmp     repeat_rolling_xor
       
finish_rolling_xor:
    ; recuparea informatilor din registre
    pop     ebx
    pop     eax 
    
    leave
    ret
    
;------------------------------------------------------------------------------
; functia hex_to_string realizeaza convertirea unui sir de carater hexazecimale
;   in binare, pentru acesta se stoceaza doua caracteri consecutive in bl si
;   bh  apoi se calculeaza valoarea lor in hexa( exemplu a = 10 )
; la final este scris pe prima pozitie valoare in binar
; exemplu ab (in hexa) este 171 in "binar"
;------------------------------------------------------------------------------ 
hex_to_string:
    push    ebp
    mov     ebp, esp
     
    ; salvare registrior folositi
    push    eax 
    push    ebx 
    push    edx
     
    mov     edx, dword [ebp + 8]; adresa unde se citeste
    mov     eax, dword [ebp + 8]; adresa unde se scrie
    xor     ebx, ebx
    
repeat_hex:
    mov     bl, byte [edx]
    test    bl, bl
    jz      finish_hex_to_string
    mov     bh, byte [edx + 1]
    cmp     bl, 'a' ; daca este litera sau "numar"
    jl      number1
    sub     bl, 'a'
    add     bl, 10
    
return1:
    cmp     bh, 'a' ; daca este litera sau "numar"
    jl      number2
    sub     bh, 'a'
    add     bh, 10
        
return2:
    shl     bl, 4
    add     bl, bh
    mov     byte [eax], bl
    inc     eax     ; deplasare pentru scrie
    add     edx, 2  ; deplasare pentru citire
    jmp     repeat_hex
        
number1:
    sub     bl, '0'
    jmp     return1
       
number2:
    sub     bh, '0'         
    jmp     return2          
    
finish_hex_to_string:
    mov     byte [eax], 0 ; terminator de sir pentru noul sir
    ; recuparea informatilor din registre    
    pop     edx
    pop     ebx
    pop     eax
                 
    leave
    ret
    
    
;------------------------------------------------------------------------------
; functia xor_hex_strings relizeaza xor intre doua siruri in hexa si decoarea
;   in-place a mesajului
; pentru a realiza aceasta functia convrteste sirului in binar folosint functia
;   hex_to_string, apoi este folosit functia de la task-ul 1  
;------------------------------------------------------------------------------     
xor_hex_strings:
    push    ebp
    mov     ebp, esp
    
    ; salvare registrior folositi
    push    eax
    push    ebx
    
    mov     eax, dword [ebp + 8]    ; string3.1
    mov     ebx, dword [ebp + 12]   ; string3.2
    
    ; conversia din "hex" in binar
    push    eax
    call    hex_to_string
    add     esp, 4
    
    ; conversia din "hex" in binar
    push    ebx
    call    hex_to_string
    add     esp, 4
    
    ; xor-ul intre cele doua siruri in "binar"
    push    ebx
    push    eax
    call    xor_strings
    add     esp, 8
   
    ; recuparea informatilor din registre 
    pop     ebx
    pop     eax
    
    leave
    ret    


;------------------------------------------------------------------------------
; functia convert_encoding_value inlocuieste caracterul cu valoarea lui, 
;   conform tabelului din enunt, iar padding('=') este inclocuit cu 0
; pentru aceasta se va compara cu 'A' prima oara(daca este litera), iar apoi
;   cu '8' daca este padding sau "numar"
; functia primeste ca parametru adresa de inceput a string-ului si lungimea
;------------------------------------------------------------------------------                       
convert_encoding_value:
    push    ebp
    mov     ebp, esp
    
    ; salvare registrior folositi
    push    eax
    push    ecx
    push    edx
    
    mov     ecx, dword [ebp + 8] ; inceputul stringului
    mov     edx, dword [ebp + 12] ; lungimea  stringului
    xor     eax, eax
    
repeat_convert:
    mov     al, byte [ecx]
    cmp     al, 'A'
    jl      nonletter
    sub     al, 'A'
    
    ; inloarcerea in loop daca nu a fost litera
return_convert:
    mov     byte [ecx], al
    inc     ecx ; deplasarea prin sir
    dec     edx
    jz      finish_convert
    jmp     repeat_convert
        
nonletter:
    cmp     al, '8'
    jg      padding
    sub     al, '2'
    add     al, 26
    jmp     return_convert
        
padding:
    sub     al, '='
    jmp     return_convert


finish_convert:
    ; recuparea informatilor din registre 
    pop     edx
    pop     ecx
    pop     eax
        
    leave
    ret


;------------------------------------------------------------------------------
; functia decod_five "transforma" cei opt byte in cinci byte originali
; functia decodeaza grupuri de cate 8 byte
; pentru scrierea celor 5 byte rezultati sau folosit registrele edx si bl
; functia primeste ca si parametru zona de memorie unde citeste cei 8 byte si
;   al doilea parametru este zona de memorie unde scrie cei 5 byte rezultati
; functia "arunca" cei mai semnificati biti din cei opt primiti si "uneste" 
;   ceilalti 5 bit in 5 byte rezultati
;------------------------------------------------------------------------------
decod_five:
    push    ebp
    mov     ebp, esp
    
    ; salvare registrior folositi
    push    eax
    push    ebx
    push    ecx
    push    edx
    
    mov     ecx, dword [ebp + 8] ; asdresa de unde se face citirea
   
    xor     eax, eax
    xor     edx, edx
    xor     ebx, ebx
            
repeat_decod_five:
    mov     al, byte [ecx]
    cmp     ah, 5 ; ah este un counter care indica numarul byte
    jge     lastpart
    or      dl, al; copierea informatie 
    shl     edx, 5; se face spatiu petru urmatori 5 bit
    
return:
    inc     ah
    inc     ecx
    cmp     ah, 8 ; daca am "decodat" 8 byte se termina loop-ul
    jz      finish
    jmp     repeat_decod_five
    
    ; "decodarea" ultimilor byte
lastpart:
    cmp     ah, 5
    je      byte_five
    cmp     ah, 6
    je      byte_six     
    or      bl, al
    jmp     return
        
byte_five:
    or      dl, al
    shl     edx, 2
    jmp     return                 
    
byte_six:
    shr     al, 3
    or      dl, al
    mov     al, byte [ecx]
    and     al, 0x07 ; 0000 0111 pentru ultimi 3 biti
    or      bl, al
    shl     bl, 5
    jmp     return
    
finish:
    mov     ecx, [ebp + 12]  ; adreasa pentru scriere
    mov     byte [ecx + 4], bl
    mov     byte [ecx + 3], dl
    mov     byte [ecx + 2], dh
    shr     edx, 8
    mov     byte [ecx + 1], dh
    shr     edx, 8
    mov     byte [ecx], dh
        
    ; recuparea informatilor din registre 
    pop     edx
    pop     ecx
    pop     ebx
    pop     eax
        
    leave
    ret

  
;------------------------------------------------------------------------------
; functia base32decode decodifica un string din base32
; functia utilizeaza strlen pentru a determina lungimea sirului, 
;   convert_encoding_value pentru a "converti" caracterele in valoarea lor
;   si decod_five pentru decoda un grup de cate 8 byte si a face decodarea 
;------------------------------------------------------------------------------       
base32decode:
    push    ebp
    mov     ebp, esp
    
    push    eax
    push    ecx
    push    edx
    
    mov     ecx, dword [ebp + 8] ; citire 
    mov     edx, dword [ebp + 8] ; scriere
    ; decodarea se face in-place
    
    ; calcularea lungimi
    push    ecx
    call    strlen
    add     esp, 4
    
    ; conversia caracterelor in valuarea lor
    push    eax ; lungime sirilor
    push    ecx ; inceputul sirlului
    call    convert_encoding_value
    add     esp, 8
    
repeat_decode_base32:
    push    edx ; adresa unde se face scrie decodificari
    push    ecx ; adresa unde se face citirea
    call    decod_five
    add     esp, 8
            
    add ecx, 8 ; deplasare scriere
    add edx, 5 ; deplasare citire
    sub eax, 8
    jz finish_base32
    jmp repeat_decode_base32
            
finish_base32:

    ; recuparea informatilor din registre 
    pop edx
    pop ecx
    pop eax
    
    leave
    ret


;------------------------------------------------------------------------------
; functia xor_on_byte realizeaza xor intre un sir de caractere si cheia pe un
; byte, decodificarea find "in-place", este asemanatoare cu functia de la task1
;------------------------------------------------------------------------------
xor_on_byte:
    push    ebp
    mov     ebp, esp
    
    ; salvare registrior folositi
    push    ebx
    push    ecx
    push    edx
    
    mov     ecx, [ebp + 8]  ; adresa unde se afla mesajul criptat
    mov     edx, [ebp + 12] ; adresa unde se afla cheia
    xor     ebx, ebx
    mov     bh, byte [edx]  ; mutarea valorie cheiei 

test_is_not_zero:       ; se repata pana cand se intalneste '\0'
    mov     bl, byte [ecx]
    test    bl, bl
    jz      finish_xor_on_byte
    xor     bl, bh
    mov     byte [ecx], bl
    inc     ecx
    jmp     test_is_not_zero
    
    
finish_xor_on_byte:
    ; recuparea informatilor din registre
    pop     edx
    pop     ecx
    pop     ebx
    
    leave
    ret
    

;------------------------------------------------------------------------------
; functia check_key verifica daca o cheie este corecta
;functia intoarce 0, daca este corect altfel 0xFF; rezultatul este intors in eax
; pentru a verifica daca este corect se realizeaza xor intre caracterele 
; stringului si cheia primiti ca si parametri, rezultatul nu este pastrat si 
; doar se cauta daca apare 'f' si 'o', 
; in bl este pus caracterul curent si in bh cheia   
;------------------------------------------------------------------------------
check_key:
    push    ebp
    mov     ebp, esp
    
    ; salvare registrior folositi
    push    ebx
    push    ecx
    push    edx
    
    mov     ecx, dword [ebp + 8]  ; adresa stringului
    mov     edx, dword [ebp + 12] ; adresa cheiei
    mov     bh, byte [edx]        ; valuare cheii
    mov     eax, 0xFF             ; valuarea de return daca nu este corecta

repeat_check:
    mov     bl, byte [ecx]        ; mutarea caracterului curent in bl
    test    bl, bl                ; verificare daca am ajuns la final
    jz      no_found_check
    xor     bl, bh                ; decriptarea caracterului
    cmp     bl, 'f'
    jz      found_check
    inc     ecx                   ; deplasare prin ecx
    jmp     repeat_check
       
found_check:
    ; verificarea daca urmatorul caracter decriptat este 'o'
    mov     bl, byte [ecx + 1]              
    xor     bl, bh
    cmp     bl, 'o'
    jnz     no_found_check
    xor     eax, eax              ; valorea de return daca cheia este buna

no_found_check:
    ; recuparea informatilor din registre
    pop     edx
    pop     ecx
    pop     ebx   
          
    leave
    ret
 

;------------------------------------------------------------------------------
; functia bruteforce_singlebyte_xor realizeaza aflarea cheie si decriptarea
;mesajului "in-place"
; functia incearca toate cheile in bucla pana cand check_key returneaza 0
;apoi functia realizeaza decriptarea "in-place" cu ajutorul functie xor_on_byte
;------------------------------------------------------------------------------              
bruteforce_singlebyte_xor:
    push    ebp
    mov     ebp, esp
    
    ; salvare registrior folositi
    push    eax
    push    ebx
    push    ecx
    push    edx
    
    mov     ebx, dword [ebp + 8] ; adresa mesajului
    mov     edx, dword [ebp + 12]; adresa key
    mov     ecx, 255             ; numarul de chei
    
repeat_brute:
    mov     dword [edx], ecx
    
    ; verificarea daca cheia este cea corecta    
    push    edx
    push    ebx
    call    check_key
    add     esp, 8
        
    cmp     eax, 0              ; daca este cheia corecta
    jz      finsih_check
    loop    repeat_brute
        
     
finsih_check:
    ; decripatrea "in-place"
    push    edx
    push    ebx
    call    xor_on_byte
    add     esp,8 
    
    ; recuparea informatilor din registre
    pop     edx
    pop     ecx
    pop     ebx
    pop     eax
            
    leave
    ret                                                                                                                                                        


;------------------------------------------------------------------------------
; functia care scrie tabela de substitutie la adresa de memorie primita 
;------------------------------------------------------------------------------
init_substitution_table:
    push    ebp
    mov     ebp, esp
    
    ; salvare registrior folositi 
    push    ecx
    
    mov     ecx, dword [ebp + 8] ; adresa unde este scrisa tabela
    ; scrierea efectiva a tabelei
    mov     byte [ecx], 'a'
    inc     ecx
    mov     byte [ecx], 'q'
    inc     ecx
    mov     byte [ecx], 'b'
    inc     ecx
    mov     byte [ecx], 'r'
    inc     ecx
    mov     byte [ecx], 'c'
    inc     ecx
    mov     byte [ecx], 'w'
    inc     ecx
    mov     byte [ecx], 'd'
    inc     ecx
    mov     byte [ecx], 'e'
    inc     ecx
    mov     byte [ecx], 'e'
    inc     ecx
    mov     byte [ecx], ' '
    inc     ecx
    mov     byte [ecx], 'f'
    inc     ecx
    mov     byte [ecx], 'u'
    inc     ecx
    mov     byte [ecx], 'g'
    inc     ecx
    mov     byte [ecx], 't'
    inc     ecx
    mov     byte [ecx], 'h'
    inc     ecx
    mov     byte [ecx], 'y'
    inc     ecx
    mov     byte [ecx], 'i'
    inc     ecx
    mov     byte [ecx], 'i'
    inc     ecx
    mov     byte [ecx], 'j'
    inc     ecx
    mov     byte [ecx], 'o'
    inc     ecx
    mov     byte [ecx], 'k'
    inc     ecx
    mov     byte [ecx], 'p'
    inc     ecx
    mov     byte [ecx], 'l'
    inc     ecx
    mov     byte [ecx], 'f'
    inc     ecx
    mov     byte [ecx], 'm'
    inc     ecx
    mov     byte [ecx], 'h'
    inc     ecx
    mov     byte [ecx], 'n'
    inc     ecx
    mov     byte [ecx], '.'
    inc     ecx
    mov     byte [ecx], 'o'
    inc     ecx
    mov     byte [ecx], 'g'
    inc     ecx
    mov     byte [ecx], 'p'
    inc     ecx
    mov     byte [ecx], 'd'
    inc     ecx
    mov     byte [ecx], 'q'
    inc     ecx
    mov     byte [ecx], 'a'
    inc     ecx
    mov     byte [ecx], 'r'
    inc     ecx
    mov     byte [ecx], 's'
    inc     ecx
    mov     byte [ecx], 's'
    inc     ecx
    mov     byte [ecx], 'l'
    inc     ecx
    mov     byte [ecx], 't'
    inc     ecx
    mov     byte [ecx], 'k'
    inc     ecx
    mov     byte [ecx], 'u'
    inc     ecx
    mov     byte [ecx], 'm'
    inc     ecx
    mov     byte [ecx], 'v'
    inc     ecx
    mov     byte [ecx], 'j'
    inc     ecx
    mov     byte [ecx], 'w'
    inc     ecx
    mov     byte [ecx], 'n'
    inc     ecx
    mov     byte [ecx], 'x'
    inc     ecx
    mov     byte [ecx], 'b'
    inc     ecx
    mov     byte [ecx], 'y'
    inc     ecx
    mov     byte [ecx], 'z'
    inc     ecx
    mov     byte [ecx], 'z'
    inc     ecx
    mov     byte [ecx], 'v'
    inc     ecx
    mov     byte [ecx], ' '
    inc     ecx
    mov     byte [ecx], 'c'
    inc     ecx
    mov     byte [ecx], '.'
    inc     ecx
    mov     byte [ecx], 'x'
    inc     ecx
    mov     byte [ecx], 0
    
    ; recuparea informatilor din registre
    pop     ecx
    
    leave
    ret

        
;------------------------------------------------------------------------------
; functia substitution_on_character cauta prin tabela de substituie caracterul
;primit ca parametru si il inlocuieste conform tabelei,
; din cauza modului de alcaturire al tabelei, literele originale pe pozitile
;pare si cele cu care sunt substituite pe poziti impare; pentru decripare
;se va cauta pe pozitia impare si substituita cu cea de pe pozitia para 
;anteriara 
;------------------------------------------------------------------------------
substitution_on_character:
    push    ebp
    mov     ebp, esp
    
    ; salvare registrior folositi 
    push    ebx
    push    ecx
    push    edx
    
    mov     ecx, dword [ebp + 8] ; adresa caracterului
    mov     edx, dword [ebp + 12]; adresa tabelei
    mov     bl,  byte [ecx]      ; caracterul care se doreste substitutia
    inc     edx                  ; inceperea cautari de pe pozitie impara
    
search_substitution:
    mov     bh, byte [edx]
    cmp     bh, bl
    jz      found_substitution
    add     edx, 2
    jmp     search_substitution
        
found_substitution:
    dec     edx
    mov     bh, byte [edx]
    mov     byte [ecx], bh
        
    ; recuparea informatilor din registre    
    pop edx
    pop ecx
    pop ebx
        
    leave
    ret

        
;------------------------------------------------------------------------------
; functia  break_substitution primeste adresa inceputului stringului si adresa
;de inceput a zonei de memorie unde se va scrie tabela de substitutie
; functia apeleaza init_substitution_table pentru scrierea tabelei
; apoi fiecare caracter este substituie folosind substitution_on_character
;------------------------------------------------------------------------------
break_substitution:
    push    ebp
    mov     ebp, esp
    
    ; salvare registrior folositi
    push    ecx
    push    edx
    
    mov     ecx, [ebp + 8]  ; string6
    mov     edx, [ebp + 12] ; adresa zonei de memorie rezervate pentru tabela

    ; scrierea tabelei la adresa de memorie primita    
    push    edx
    call    init_substitution_table
    add     esp, 4
   
    ; calcularea lungime sirului
    push    ecx
    call    strlen
    add     esp, 4
    
repeat_substitution_character:
    ; decriptarea caracter cu caracter
    push    edx
    push    ecx
    call    substitution_on_character
    add     esp, 8
        
    inc     ecx ; deplasarea prin string
    dec     eax
    jnz     repeat_substitution_character
    
    pop     edx
    pop     ecx
    
    ; recuparea informatilor din registre 
    leave
    ret
    
                        
main:
    push    ebp
    mov     ebp, esp
    sub     esp, 2300
    
    ; fd = open("./input.dat", O_RDONLY);
    mov     eax, 5
    mov     ebx, filename
    xor     ecx, ecx
    xor     edx, edx
    int     0x80
    
	; read(fd, ebp-2300, inputlen);
	mov    ebx, eax
	mov    eax, 3
	lea    ecx, [ebp-2300]
	mov    edx, [inputlen]
	int    0x80

	; close(fd);
	mov    eax, 6
	int    0x80

        ; TASK 1: Simple XOR between two byte streams
        ; calcularea lungimi string1.1
        push    ecx
        call    strlen
        add     esp, 4
        
        ; calcularea adresei string1.2
        lea     edx, [ecx + eax + 1]

	push   edx
	push   ecx
	call   xor_strings
	add    esp, 8

        ; Print the first resulting string
        ; salvarea registrilor inainte de printarare
        push    eax
        push    ecx
        push    edx
        
	push   ecx
	call   puts
	add    esp, 4

        ; recuperarea registrilor dupa printare
        pop     edx
        pop     ecx
        pop     eax


        ; TASK 2: Rolling XOR
        ; adresa de memorie pentru string2
        lea     ecx, [edx + eax + 1]
        
        ; deternimare lugimi string2
        push    ecx
        call    strlen
        add     esp, 4
       
	push   ecx
	call   rolling_xor
	add    esp, 4

	; Print the second resulting string
        ; salvarea registrilor inainte de printarare
        push    eax
        push    ecx
        push    edx
        
        push    ecx ; string2 decodificat
	call   puts
	add    esp, 4

        ; recuperarea registrilor dupa printare
        pop     edx
        pop     ecx
        pop     eax

	
	; TASK 3: XORing strings represented as hex strings
	; adresa de memorie pentru string3.1
        lea     ecx, [ecx + eax + 1]
        
        ; lungime string3.1
        push    ecx
        call    strlen
        add     esp, 4
        
        ; adresa de memorie pentru string3.2
        lea     edx, [ecx + eax + 1]
        
	push   edx
	push   ecx
	call   xor_hex_strings
	add    esp, 8

	; Print the third string
        ; salvarea registrilor inainte de printarare
        push    eax
        push    ecx
        push    edx
        
	push   ecx
	call   puts
	add    esp, 4

        ; recuperarea registrilor dupa printare
        pop     edx
        pop     ecx
        pop     eax
	

	; TASK 4: decoding a base32-encoded string
	lea    ecx, [ edx + eax + 1] ; adreasa string4
    
        ; calcularea lungimi string4
        push    ecx
        call    strlen
        add     esp, 4	

        push    ecx 
	call   base32decode
	add    esp, 4

	; Print the fourth string
        ; salvarea registrilor inainte de printarare
        push    eax
        push    ecx
        push    edx

	push   ecx
	call   puts
	add    esp, 4

        ; recuperarea registrilor dupa printare
        pop     edx
        pop     ecx
        pop     eax


	; TASK 5: Find the single-byte key used in a XOR encoding
	lea    ecx, [ecx + eax + 1] ; adresa string5

        ; calcularea lungimi string5
        push    ecx
        call    strlen
        add     esp, 4
        
        ; alocarea memriei pentru cheia
        sub     esp, 4                ; alocarea memorie pentru key
        lea     edx, [ebp - 2300 - 4] ; adresa key
        
	push 	edx
	push 	ecx
	call 	bruteforce_singlebyte_xor
	add 	esp, 8

        ; Print the fifth string and the found key value
        ; salvarea registrilor inainte de printarare
        push    eax
        push    ecx
        push    edx

	push   ecx
	call   puts
	add    esp, 4

        ; recuperarea registrilor dupa printare
        pop     edx
        pop     ecx
        pop     eax

        mov    ebx, dword [edx] ; valuarea cheie
        ; salvarea registrilor inainte de printarare
        push    eax
        push    ecx
        push    edx
        
	push   ebx
	push   fmtstr
	call   printf
	add    esp, 8

        ; recuperarea registrilor dupa printare
        pop     edx
        pop     ecx
        pop     eax
        
        add     esp, 4  ; eliberarea memorie pentru cheia


	; TASK 6: Break substitution cipher
	lea    ecx, [ecx + eax + 1] ; adresa string6
	
        ; rezervarea spatiului pentru tabela si terminatorul de sir
        sub     esp, 57
        lea     edx , [esp] ; adresa spatiului pentru tabela
        
	push   edx
	push   ecx
	call   break_substitution
	add    esp, 8
    
        ; salvarea registrilor inainte de printarare
        push    edx
	; Print final solution (after some trial and error)
	push   ecx
	call   puts
	add    esp, 4

        ; recuperarea registrilor dupa printare
        pop     edx
	; Print substitution table
	push   edx
	call   puts
	add    esp, 4

         add esp, 57 ; eliberarea memorie pentru tabela
	; Phew, finally done
    xor eax, eax
    mov esp, ebp
    
    leave
    ret
