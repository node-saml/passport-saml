module.exports = {
  dataSource: "prs",
  prefix: "",
  onlyMilestones: false,
  ignoreTagsWith: ["beta"],
  ignoreLabels: [
    "closed",
    "breaking-change",
    "enhancement",
    "deprecation",
    "dependencies",
    "bug",
    "documentation",
    "tests",
    "chore",
    "javascript",
    "github_actions",
  ],
  ignoreIssuesWith: ["duplicate"],
  tags: "all",
  groupBy: {
    "Major Changes": ["breaking-change"],
    "Minor Changes": ["enhancement"],
    Deprecations: ["deprecation"],
    Dependencies: ["dependencies"],
    "Bug Fixes": ["bug", "security"],
    Documentation: ["documentation"],
    Tests: ["tests"],
    "Technical Tasks": ["chore"],
    Other: ["..."],
  },
  changelogFilename: "CHANGELOG.md",
  username: "node-saml",
  repo: "passport-saml",
  template: {
    issue: function (placeholders) {
      const parts = [
        "-",
        placeholders.labels,
        placeholders.name,
        `[${placeholders.text}](${placeholders.url})`,
      ];
      return parts
        .filter((_) => _)
        .join(" ")
        .replace("  ", " ");
    },
    release: function (placeholders) {
      placeholders.body = placeholders.body.replace(
        "*No changelog for this release.*",
        "\n_No changelog for this release._",
      );
      return `## ${placeholders.release} (${placeholders.date})\n${placeholders.body}`;
    },
    group: function (placeholders) {
      const iconMap = {
        Enhancements: "🚀",
        "Minor Changes": "🚀",
        Deprecations: "⚠️",
        "Bug Fixes": "🐛",
        Documentation: "📚",
        Tests: "🧪",
        "Technical Tasks": "⚙️",
        "Major Changes": "💣",
        Dependencies: "🔗",
      };
      const icon = iconMap[placeholders.heading] || "🙈";
      return "\n#### " + icon + " " + placeholders.heading + "\n";
    },
  },
};
