.intel_syntax noprefix
.global	hook_code
hook_code:
		mov	ax, cs
		cmp	ax, 0x33
		jne	__gogo
		jmp	$
__gogo:
		push	eax
		push	ecx
		push	edx
		push	ebx
		push	ebp
		push	esi
		push	edi
		mov	eax, [ebp-0x1028]
		push	eax
		call	hook_function
		add	esp, 4	

		pop	edi
		pop	esi
		pop	ebp
		pop	ebx
		pop	edx
		pop	ecx
		pop	eax
		push	0x933+0x56555000
		jmp	[ebp-0x1028]		
