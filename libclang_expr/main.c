#include <clang-c/Index.h>
#include <clang-c/CXCompilationDatabase.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "preprocessor.h"

#define MAX_EXPRESSION_SIZE 4096
#define ONE 1

typedef struct {
    CXTranslationUnit tu;
    CXFile file;
    CXSourceLocation target;
    CXCursor best_cursor;
} SearchData;

int location_in_cursor(CXCursor cursor, SearchData* data)
{
    CXSourceRange range = clang_getCursorExtent(cursor);

    CXSourceLocation start = clang_getRangeStart(range);
    CXSourceLocation end   = clang_getRangeEnd(range);

    unsigned s_line, s_col, e_line, e_col, t_line, t_col;
    CXFile file;

    clang_getExpansionLocation(start, &file, &s_line, &s_col, NULL);
    clang_getExpansionLocation(end, &file, &e_line, &e_col, NULL);
    clang_getExpansionLocation(data->target, &file, &t_line, &t_col, NULL);

    if(t_line < s_line || t_line > e_line)
    {
        return 0;
    }

    if(t_line == s_line && t_col < s_col)
    {
        return 0;
    }

    if(t_line == e_line && t_col > e_col)
    {
        return 0;
    }

    return 1;
}


int is_expression(enum CXCursorKind kind)
{
    switch(kind)
    {
        case CXCursor_DeclRefExpr:
        case CXCursor_MemberRefExpr:
        case CXCursor_ArraySubscriptExpr:
        case CXCursor_ParenExpr:
        case CXCursor_CStyleCastExpr:
        case CXCursor_UnexposedExpr:
        case CXCursor_UnaryOperator:
        case CXCursor_BinaryOperator:
            return 1;
        default:
            return 0;
    }
}

enum CXChildVisitResult visitor(CXCursor cursor, CXCursor __attribute__((unused)) parent, CXClientData client_data)
{
    SearchData* data = (SearchData*)client_data;

    if(is_expression(clang_getCursorKind(cursor)))
    {
        if(location_in_cursor(cursor, data))
        {
            data->best_cursor = cursor;
        }
    }

    return CXChildVisit_Recurse;
}

CXSourceRange normalize_range_to_expansion(CXTranslationUnit tu, CXSourceRange range)
{
    CXSourceLocation start = clang_getRangeStart(range);
    CXSourceLocation end   = clang_getRangeEnd(range);

    CXFile sfile, efile;
    unsigned sline, scol, soff;
    unsigned eline, ecol, eoff;

    clang_getExpansionLocation(start, &sfile, &sline, &scol, &soff);
    clang_getExpansionLocation(end, &efile, &eline, &ecol, &eoff);

    // If macro caused start to be outside the file, force same file
    if(!sfile)
    {
        sfile = efile;
    }

    CXSourceLocation new_start = clang_getLocationForOffset(tu, sfile, soff);
    CXSourceLocation new_end   = clang_getLocationForOffset(tu, efile, eoff);

    return clang_getRange(new_start, new_end);
}

char* get_source_text(CXTranslationUnit tu, CXSourceRange range)
{
    CXToken* tokens     = NULL;
    unsigned num_tokens = 0;

    clang_tokenize(tu, range, &tokens, &num_tokens);

    if(num_tokens == 0)
    {
        return NULL;
    }

    size_t total = 0;

    for(unsigned i = 0; i < num_tokens; i++)
    {
        CXString s  = clang_getTokenSpelling(tu, tokens[i]);
        total      += strlen(clang_getCString(s)) + 1;
        clang_disposeString(s);
    }

    char* result = malloc(total + 1);
    if(result == NULL)
    {
        return NULL;
    }
    result[0] = '\0';

    for(unsigned i = 0; i < num_tokens; i++)
    {
        CXString s = clang_getTokenSpelling(tu, tokens[i]);
        strcat(result, clang_getCString(s));
        clang_disposeString(s);
    }

    clang_disposeTokens(tu, tokens, num_tokens);

    return result;
}

int main(int argc, char** argv)
{
    if(argc < 4)
    {
        printf("usage: %s file.c line column\n", argv[0]);
        return 1;
    }

    const char* filename = argv[ONE];
    int line             = atoi(argv[2]);
    int column           = atoi(argv[3]);

    CXIndex index = clang_createIndex(1, 0);

    char** args = NULL;
    size_t args_count = 0;
    CXCompilationDatabase db;

    db = clang_CompilationDatabase_fromDirectory(".vscode/", NULL);
    if(db == NULL)
    {
        db = clang_CompilationDatabase_fromDirectory(".", NULL);
    }
    if(db != NULL)
    {
        CXCompileCommands cmds   = clang_CompilationDatabase_getCompileCommands(db, filename);
        CXCompileCommand cmd     = clang_CompileCommands_getCommand(cmds, 0);

        unsigned num_args = clang_CompileCommand_getNumArgs(cmd);
        args = calloc(num_args-1, sizeof(char*));
        for(unsigned i = 1; i < num_args; i++)
        {
            CXString arg = clang_CompileCommand_getArg(cmd, i);
            const char* carg = clang_getCString(arg);
            if(strcmp(carg, "--") == 0)
            {
                clang_disposeString(arg);
                break;
            }
            args[args_count] = strdup(carg);
            args_count++;
            clang_disposeString(arg);
        }
        clang_CompileCommands_dispose(cmds);
        clang_CompilationDatabase_dispose(db);
    }
    else
    {
        args_count = 1;
        args = calloc(1, sizeof(char*));
        args[0] = malloc(8);
        strcpy(args[0], "-c");
    }

    CXTranslationUnit tu =
        clang_parseTranslationUnit(index, filename, (const char**)args, args_count, NULL, 0, CXTranslationUnit_None);

    for(size_t i = 0; i < args_count; i++)
    {
        free(args[i]);
        args[i] = NULL;
    }
    free(args);
    args = NULL;

    if(!tu)
    {
        return 1;
    }

    CXFile file               = clang_getFile(tu, filename);
    CXSourceLocation location = clang_getLocation(tu, file, line, column);

    SearchData data;
    data.tu          = tu;
    data.file        = file;
    data.target      = location;
    data.best_cursor = clang_getNullCursor();

    CXCursor root = clang_getTranslationUnitCursor(tu);
    clang_visitChildren(root, visitor, &data);

    if(clang_Cursor_isNull(data.best_cursor))
    {
        // No expression found
        goto cleanup;
    }
    CXSourceRange raw_range = clang_getCursorExtent(data.best_cursor);
    CXSourceLocation start  = clang_getRangeStart(raw_range);

    // If the expression starts with a macro expansion token,
    // check whether our target column falls within that macro token.
    CXFile exp_file, spell_file;
    unsigned exp_line, exp_col, exp_off;
    unsigned spell_line, spell_col, spell_off;

    clang_getExpansionLocation(start, &exp_file, &exp_line, &exp_col, &exp_off);
    clang_getSpellingLocation(start, &spell_file, &spell_line, &spell_col, &spell_off);

    CXSourceRange range = normalize_range_to_expansion(tu, raw_range);
    char* text          = get_source_text(tu, range);
    if(text)
    {
        CXFile file;
        unsigned line, column, offset;
        clang_getSpellingLocation(clang_getRangeStart(range), &file, &line, &column, &offset);
        size_t file_size;
        const char *buffer = clang_getFileContents(tu, file, &file_size);
        char* preprocessed = preprocess_expression(buffer, offset, text);

        printf("%s\n%s\n", text, preprocessed);

        free(text);
        free(preprocessed);
    }
    else
    {
        printf("\n\n");
    }


cleanup:
    clang_disposeTranslationUnit(tu);
    clang_disposeIndex(index);
    return 0;
}
