// Lighthouse CI configuration (T12 / cross-cutting §⑧).
//
// Scores the 7 SPA pages against a performance/accessibility budget. Run via
// `lhci autorun` after `npm run build` (it serves ./dist itself). Scores below
// 0.8 produce a WARNING (not a failure) - this is a regression tripwire.
// NOTE: SPA client routes need the static server's index.html fallback; verify
// on a real CI run that each route renders before treating scores as authoritative.
module.exports = {
  ci: {
    collect: {
      staticDistDir: "./dist",
      numberOfRuns: 1,
      url: [
        "http://localhost/",
        "http://localhost/assessments/new",
        "http://localhost/assessments/sample",
        "http://localhost/approvals",
        "http://localhost/findings",
        "http://localhost/case-studio",
        "http://localhost/updates",
      ],
    },
    assert: {
      assertions: {
        "categories:performance": ["warn", { minScore: 0.8 }],
        "categories:accessibility": ["warn", { minScore: 0.8 }],
      },
    },
    upload: {
      target: "temporary-public-storage",
    },
  },
};
