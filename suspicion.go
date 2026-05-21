package main

import "math"

// suspicion is a phi-accrual-style detector for how the target host is
// answering tiptoe. It is adapted from the distributed-systems failure
// detector of Hayashibara et al. (2004) — the same detector Cassandra and Akka
// use to decide a cluster node has gone down.
//
// A fixed RTT threshold is brittle. Set it tight and a naturally jittery host
// trips it constantly; set it loose and a rock-steady host can degrade a long
// way before it fires. The phi-accrual detector removes the guess: it LEARNS
// the distribution of how the host normally answers, from a sliding window of
// samples, and scores every new observation on a continuous logarithmic
// surprise scale, phi:
//
//	phi = -log10( P(an honest response is at least this slow) )
//
// phi = 1  -> roughly a 10%  chance the host is merely slow, not stressed.
// phi = 2  -> roughly a 1%   chance.
// phi = 3  -> roughly a 0.1% chance.
//
// Because the distribution is re-estimated every probe, the detector adapts on
// its own: a jittery host earns a wide tolerance, a steady host a tight one.
// tiptoe reads a rising phi as the host turning hostile and slows down before
// any hard cutoff is reached.
type suspicion struct {
	window []float64 // recent RTT samples, in milliseconds
	size   int       // sliding-window capacity
	minStd float64   // floor on the standard deviation
}

func newSuspicion(size int) *suspicion {
	return &suspicion{size: size, minStd: 5.0}
}

// observe records one honest RTT sample — a probe the host actually answered.
func (s *suspicion) observe(rttMs float64) {
	s.window = append(s.window, rttMs)
	if len(s.window) > s.size {
		s.window = s.window[len(s.window)-s.size:]
	}
}

// ready reports whether enough samples have accumulated for phi to mean
// anything. Below this, the detector is still learning the host's baseline.
func (s *suspicion) ready() bool { return len(s.window) >= 4 }

// stats returns the mean and standard deviation of the sample window. The
// standard deviation is floored by minStd so an all-but-identical window does
// not collapse the distribution to a spike.
func (s *suspicion) stats() (mean, std float64) {
	n := float64(len(s.window))
	if n == 0 {
		return 0, s.minStd
	}
	for _, v := range s.window {
		mean += v
	}
	mean /= n
	for _, v := range s.window {
		d := v - mean
		std += d * d
	}
	std = math.Sqrt(std / n)
	if std < s.minStd {
		std = s.minStd
	}
	return mean, std
}

// phi scores how surprising it is for an honest host to take valueMs to
// answer, given everything the detector has learned. A normal RTT scores near
// zero; an RTT — or a silence, passed as the elapsed wait — far out in the
// distribution's tail scores high.
func (s *suspicion) phi(valueMs float64) float64 {
	mean, std := s.stats()
	p := 1 - normalCDF(valueMs, mean, std) // P(an honest response is >= valueMs)
	if p < 1e-12 {
		p = 1e-12
	}
	return -math.Log10(p)
}

// normalCDF is the cumulative distribution function of Normal(mean, std),
// expressed through the error function from the standard library.
func normalCDF(x, mean, std float64) float64 {
	return 0.5 * (1 + math.Erf((x-mean)/(std*math.Sqrt2)))
}
