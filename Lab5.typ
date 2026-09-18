#import "@preview/wordometer:0.1.5": word-count, total-words
#show: word-count

#let title = "Lab 5, Attack vibecoded websites"
#let course = "Cyber Security: Defence against the Dark Arts"
#let author = "Erik Törnudd, Niko Schuppan-Cruz"

#set document(title: title, author: author)
#set page(
  paper: "a4",
  margin: (top: 3cm, bottom: 2.5cm, left: 2.5cm, right: 2.5cm),
  numbering: "1",
)
#set text(font: "New Computer Modern", size: 11pt, lang: "en")
#set par(justify: true, leading: 0.65em)
//#set heading(numbering: "1.1")

// Title block
#align(center)[
  #text(size: 20pt, weight: "bold")[#title]

  #v(0.3cm)
  #text(size: 12pt, style: "italic")[#course]

  #v(0.2cm)
  #text(size: 10pt)[#author --- #datetime.today().display("[day] [month repr:long] [year]")]
]

#v(1cm)

= Report