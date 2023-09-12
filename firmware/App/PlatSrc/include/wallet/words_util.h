#ifndef TRUNK_WORDSUTILS_H
#define TRUNK_WORDSUTILS_H

#define RANGE_INVALID_VALUE -1

#ifdef __cplusplus
extern "C" {
#endif
typedef struct _range {
    int startIndex;
    int endIndex;
} Range; 

int getCntOfRange(const Range *range);

int getWordRange(const char *prefix, Range *result);

int checkWord(const char *str);

#ifdef __cplusplus
}
#endif
#endif
