//
//  percentile.h
//  appFirewall
//
// original cormode paper: https://www.cs.rutgers.edu/~muthu/bquant.pdf
// implementation is from https://github.com/statsite/statsite/tree/master/src

/*
BSD 3-Clause
Copyright (c) 2012, Armon Dadgar
All rights reserved.
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the organization nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL ARMON DADGAR BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef percentile_h
#define percentile_h

/**
 * This module implements the Cormode-Muthukrishnan algorithm
 * for computation of biased quantiles over data streams from
 * "Effective Computation of Biased Quantiles over Data Streams"
 *
 */
#ifndef CM_QUANTILE_H
#define CM_QUANTILE_H
#include <stdint.h>
#include <stdio.h>
#include <iso646.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <limits.h>
#include <stdio.h>
#include "heap.h"

typedef struct cm_sample {
    double value;       // The sampled value
    uint64_t width;     // The number of ranks represented
    uint64_t delta;     // Delta between min/max rank
    struct cm_sample *next;
    struct cm_sample *prev;
} cm_sample;

struct cm_insert_cursor {
    cm_sample *curs;
};

struct cm_compress_cursor {
    cm_sample *curs;
    uint64_t min_rank;
};

typedef struct {
    double eps;  // Desired epsilon

    double *quantiles;      // Queryable quantiles, sorted array
    uint32_t num_quantiles; // Number of quantiles

    uint64_t num_samples;   // Number of samples
    uint64_t num_values;    // Number of values added

    cm_sample *samples;     // Sorted linked list of samples
    cm_sample *end;         // Pointer to the end of the sampels
    heap *bufLess, *bufMore;// Sample buffer

    struct cm_insert_cursor insert;     // Insertion cursor
    struct cm_compress_cursor compress; // Compression cursor
} cm_quantile;


/**
 * Initializes the CM quantile struct
 * @arg eps The maximum error for the quantiles
 * @arg quantiles A sorted array of double quantile values, must be on (0, 1)
 * @arg num_quants The number of entries in the quantiles array
 * @arg cm_quantile The cm_quantile struct to initialize
 * @return 0 on success.
 */
int init_cm_quantile(double eps, double *quantiles, uint32_t num_quants, cm_quantile *cm);

/**
 * Destroy the CM quantile struct.
 * @arg cm_quantile The cm_quantile to destroy
 * @return 0 on success.
 */
int destroy_cm_quantile(cm_quantile *cm);

/**
 * Adds a new sample to the struct
 * @arg cm_quantile The cm_quantile to add to
 * @arg sample The new sample value
 * @return 0 on success.
 */
int cm_add_sample(cm_quantile *cm, double sample);

/**
 * Queries for a quantile value
 * @arg cm_quantile The cm_quantile to query
 * @arg quantile The quantile to query
 * @return The value on success or 0.
 */
double cm_query(cm_quantile *cm, double quantile);

/**
 * Forces the internal buffers to be flushed,
 * this allows query to have maximum accuracy.
 * @arg cm_quantile The cm_quantile to add to
 * @return 0 on success.
 */
int cm_flush(cm_quantile *cm);

#endif

#endif /* percentile_h */
