#ifndef SENKO_TIME_H
#define SENKO_TIME_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* milliseconds from an arbitrary fixed point, never from the wall clock.
   deadlines built on gettimeofday() break twice on armv7: time_t is 32 bit
   there, so tv_sec * 1000 overflows a signed long, and an ios 5 device that
   corrects a dead rtc right after it joins wifi moves the wall clock under
   every deadline already in flight. int64 keeps the arithmetic exact on both
   slices */
int64_t senko_now_ms(void);

#ifdef __cplusplus
}
#endif

#endif /* senko_time_h */
