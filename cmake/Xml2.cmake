# Compile only the exact parser verified by the unchanged 99-file source lock.
include("${CMAKE_CURRENT_LIST_DIR}/Xml2Source.cmake")

add_library(nexus-xml2 STATIC
    "${XML2_SOURCE}/HTMLparser.c"
    "${XML2_SOURCE}/HTMLtree.c"
    "${XML2_SOURCE}/SAX.c"
    "${XML2_SOURCE}/SAX2.c"
    "${XML2_SOURCE}/buf.c"
    "${XML2_SOURCE}/catalog.c"
    "${XML2_SOURCE}/chvalid.c"
    "${XML2_SOURCE}/debugXML.c"
    "${XML2_SOURCE}/dict.c"
    "${XML2_SOURCE}/encoding.c"
    "${XML2_SOURCE}/entities.c"
    "${XML2_SOURCE}/error.c"
    "${XML2_SOURCE}/globals.c"
    "${XML2_SOURCE}/hash.c"
    "${XML2_SOURCE}/list.c"
    "${XML2_SOURCE}/parser.c"
    "${XML2_SOURCE}/parserInternals.c"
    "${XML2_SOURCE}/pattern.c"
    "${XML2_SOURCE}/relaxng.c"
    "${XML2_SOURCE}/threads.c"
    "${XML2_SOURCE}/tree.c"
    "${XML2_SOURCE}/uri.c"
    "${XML2_SOURCE}/valid.c"
    "${XML2_SOURCE}/xinclude.c"
    "${XML2_SOURCE}/xmlIO.c"
    "${XML2_SOURCE}/xmlmemory.c"
    "${XML2_SOURCE}/xmlreader.c"
    "${XML2_SOURCE}/xmlregexp.c"
    "${XML2_SOURCE}/xmlsave.c"
    "${XML2_SOURCE}/xmlschemas.c"
    "${XML2_SOURCE}/xmlschemastypes.c"
    "${XML2_SOURCE}/xmlstring.c"
    "${XML2_SOURCE}/xmlunicode.c"
    "${XML2_SOURCE}/xpath.c"
    "${XML2_SOURCE}/xpointer.c")
target_include_directories(nexus-xml2 PUBLIC "${XML2_SOURCE}/include")
target_compile_definitions(nexus-xml2 PUBLIC LIBXML_STATIC PRIVATE HAVE_VA_COPY)
set_target_properties(nexus-xml2 PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON)
