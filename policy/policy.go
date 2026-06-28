package policy

import (
    "blackbox/archive"
    "blackbox/store"
)

type DepCheckResult struct {
    DependencyName    string
    DependencyVersion string
    Blocked           bool
    Reason            string
}

func CheckDependencies(s *store.Store, deps []archive.Dependency) ([]DepCheckResult, error) {
    if s == nil {
        return nil, nil
    }
    var results []DepCheckResult
    for _, d := range deps {
        r := DepCheckResult{
            DependencyName:    d.Name,
            DependencyVersion: d.Version,
        }
        blocked, err := s.IsVersionBlocked(d.Name, d.Version)
        if err != nil {
            return nil, err
        }
        if blocked {
            r.Blocked = true
            reason, _ := s.GetBlockedReason(d.Name, d.Version)
            r.Reason = reason
            if r.Reason == "" {
                r.Reason = "blocked dependency"
            }
        }
        results = append(results, r)
    }
    return results, nil
}
