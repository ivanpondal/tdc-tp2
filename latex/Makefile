.PHONY: all clean clean_aux

TEX=informe.tex sections/1-introduccion.tex
PDF=informe

# LaTeX flags
TEXFLAGS=-file-line-error -interaction=nonstopmode

all: $(PDF)

$(PDF): $(TEX)
	@ [ ! -f $(PDF).aux ] || md5sum $(PDF).aux > .auxmd5
	# [ ! -f $(PDF).aux ] || bibtex $(PDF).aux
	@ pdflatex $(TEXFLAGS) -jobname $(PDF) $<
	@ if [ "x$(shell cat .auxmd5)" '!=' "x$(shell md5sum $(PDF).aux)" ]; then echo "Relatexing..." 1>&2; rm $@.pdf; make $@; fi

clean: clean_aux
	rm -f $(PDF)

clean_aux:
	find . -name "*.aux" -delete \
	    -o -name "*.log" -delete \
	    -o -name "*.out" -delete \
	    -o -name "*.toc" -delete \
	    -o -name "*.nav" -delete \
	    -o -name "*.snm" -delete \
	    -o -name "*.fls" -delete \
	    -o -name "*.fdb_latexmk" -delete
