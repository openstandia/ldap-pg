package main

import (
	"strconv"
)

type PPolicy struct {
	PwdAttribute       []string `json:"pwdAttribute"`
	PwdLockout         []string `json:"pwdLockout"`
	PwdLockoutDuration []string `json:"pwdLockoutDuration"`
	PwdMaxFailure      []string `json:"pwdMaxFailure"`
}

func (p *PPolicy) IsLockoutEnabled() bool {
	return len(p.PwdLockout) > 0 && p.PwdLockout[0] == "TRUE" && p.MaxFailure() > 0
}

func (p *PPolicy) ShouldLockout(current int) bool {
	return p.IsLockoutEnabled() && current+1 >= p.MaxFailure()
}

func (p *PPolicy) LockoutDuration() int64 {
	if len(p.PwdLockoutDuration) > 0 {
		i, err := strconv.ParseInt(p.PwdLockoutDuration[0], 10, 64)
		if err != nil {
			return 0
		}
		return i
	}
	return 0
}

func (p *PPolicy) MaxFailure() int {
	if len(p.PwdMaxFailure) > 0 {
		i, err := strconv.Atoi(p.PwdMaxFailure[0])
		if err != nil {
			return 0
		}
		return i
	}
	return 0
}
