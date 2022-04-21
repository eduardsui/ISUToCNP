# ISUToCNP
Extragerea CNP-ului din identificatorul unic statistic (ISU) folosit de Institutul National de Statistica

# La ce foloseste?
Institutul National de Statatistica (ISU) centralizeaza datele de rececensamant 2022 folosind Identificatorul Unic Statistic (ISU) ce nu este altceva decat functia `sha1` aplicata pe CNP. Avand in vedere ca se colecteaza sexul, data nasterii, extragerea CNP-ului din ISU devine o problema triviala.

# Compilare

`gcc -O3 ISUtoCNP.c -o ISUtoCNP`

# Utilizare

Exista 2 cazuri de utilizare:

1. Sexul si data nasterii sunt cunoscute:

``ISUtoCNP 421069c132f4a7801ec2319b8052cea1941412af 2410223``

2. Sexul si data nasterii nu sunt cunoscute:

``ISUtoCNP 421069c132f4a7801ec2319b8052cea1941412af``

Daca sexul si data nasterii sunt cunoscute, timpul de executie este sub 5 milisecunde. In cazul 2, timpul de obtinere a CNP-ului are o medie de 5 minute folosind o statie de lucru uzuala.

CNP-ul folosit in exemplu este cel oferit chiar de INS pentru a testa "algoritmul de criptare".

# Motivatie

Publicarea acestei vulnerabilitati este necesara pentru ca specialistii INS sa poata confirma si remedia problema.
