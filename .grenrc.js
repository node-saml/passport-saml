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
  ],
  tags: "all",
  groupBy: {
    "Major Changes: ": ["semver-major", "breaking-change"],
    "Minor Changes: ": ["semver-minor"],
    "Bug Fixes: ": ["semver-patch", "bug"],
    "Other: ": ["..."],
  },
  changelogFilename: "CHANGELOG.md",
  username: "node-saml",
  repo: "passport-saml",
  template: {
    release: function (placeholders) {
      let dateParts = placeholders.date.split("/");
      let placeholdersDate = new Date(
        Number(dateParts[2]),
        Number(dateParts[1]) - 1,
        Number(dateParts[0])
      );
      let isoDateString = placeholdersDate.toISOString().split("T")[0];
      return `## ${placeholders.release} (${isoDateString})\n${placeholders.body}`;
    },
  },
};
