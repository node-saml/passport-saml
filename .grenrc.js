module.exports = {
  dataSource: "prs",
  prefix: "",
  onlyMilestones: false,
  ignoreTagsWith: ["v0.32.0", "0.0.3"],
  ignoreLabels: [
    "semver-major",
    "semver-minor",
    "semver-patch",
    "closed",
    "breaking-change",
    "bug",
    "enhancement",
    "dependencies",
  ],
  tags: "all",
  groupBy: {
    "Major Changes": ["semver-major", "breaking-change"],
    "Minor Changes": ["semver-minor", "enhancement"],
    Dependencies: ["dependencies"],
    "Bug Fixes": ["semver-patch", "bug"],
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
      return parts.filter((_) => _).join(" ");
    },
    release: function (placeholders) {
      let dateParts = placeholders.date.split("/");
      let placeholdersDate = new Date(
        Number(dateParts[2]),
        Number(dateParts[1]) - 1,
        Number(dateParts[0])
      );
      let isoDateString = placeholdersDate.toISOString().split("T")[0];
      placeholders.body = placeholders.body.replace(
        "*No changelog for this release.*",
        "\n_No changelog for this release._"
      );
      return `## ${placeholders.release} (${isoDateString})\n${placeholders.body}`;
    },
    group: function (placeholders) {
      const iconMap = {
        Enhancements: "🚀",
        "Minor Changes": "🚀",
        "Bug Fixes": "🐛",
        Documentation: "📚",
        "Technical Tasks": "⚙️",
        "Major Changes": "💣",
        Dependencies: "🔗",
      };
      const icon = iconMap[placeholders.heading] || "🙈";
      return "\n#### " + icon + " " + placeholders.heading + ":\n";
    },
  },
};
