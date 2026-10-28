PAPER := leanseal

.PHONY: all clean distclean

all: $(PAPER).pdf

$(PAPER).pdf: $(PAPER).tex macros.tex references.bib $(wildcard sections/*.tex) $(wildcard figures/*.tex)
	latexmk -pdf -interaction=nonstopmode -halt-on-error $(PAPER).tex

clean:
	latexmk -C $(PAPER).tex
	rm -f $(PAPER).bbl $(PAPER).run.xml

distclean: clean
