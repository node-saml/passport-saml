module.exports = {
  dataSource: "prs",
  prefix: "",
  onlyMilestones: false,
  ignoreTagsWith: ["v0.32.0", "0.0.3"],
  tags: "all",
  groupBy: false,
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
