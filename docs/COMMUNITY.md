# MetaFuse Community Guide

Welcome to the MetaFuse community! This guide helps you participate in the project and connect with other users and contributors.

---

## Community Channels

### GitHub Discussions

Our primary community forum for conversations, questions, and sharing:

**[Join GitHub Discussions](https://github.com/ethan-tyler/MetaFuse/discussions)**

**Categories:**

- **Announcements**: Updates from maintainers about releases, roadmap changes, and important news
- **General**: Chat about anything MetaFuse-related
- **Ideas**: Share ideas for new features and improvements
- **Q&A**: Ask questions and get help from the community
- **Show and tell**: Share your MetaFuse projects and integrations
- **Polls**: Community votes on features and priorities

### GitHub Issues

For bug reports, feature requests, and technical proposals:

**[Browse Issues](https://github.com/ethan-tyler/MetaFuse/issues)**

**How to contribute:**

1. **Bug Reports**: Use the [bug report template](.github/ISSUE_TEMPLATE/bug_report.yml)
   - Check existing issues first to avoid duplicates
   - Provide reproduction steps and environment details
   - Include error messages and logs

2. **Feature Requests**: Use the [feature request template](.github/ISSUE_TEMPLATE/feature_request.yml)
   - Explain the use case and motivation
   - Describe the desired behavior
   - Consider backward compatibility

3. **RFCs** (Request for Comments): Use the [RFC template](.github/ISSUE_TEMPLATE/rfc.yml)
   - For significant design proposals
   - Include technical design and alternatives considered
   - Gather community feedback before implementation

### Contributing Code

Ready to contribute? See our [Contributing Guide](../CONTRIBUTING.md) for:

- Development setup
- Coding standards
- Testing requirements
- Pull request process

**Good First Issues**: Look for issues labeled `good-first-issue` to get started.

---

## How to Get Help

### 1. Check Documentation First

- [Getting Started Guide](getting-started.md)
- [API Reference](api-reference.md)
- [For Developers](for-developers.md)
- [Migration Guides](MIGRATION-v0.4.md)
- [Security Documentation](SECURITY.md)

### 2. Search Existing Issues and Discussions

Before asking a question, search to see if it's already been answered:

- [Search Issues](https://github.com/ethan-tyler/MetaFuse/issues)
- [Search Discussions](https://github.com/ethan-tyler/MetaFuse/discussions)

### 3. Ask in GitHub Discussions

If you can't find an answer, post in the **Q&A** category:

- Provide context about what you're trying to achieve
- Include relevant code snippets and configuration
- Mention your MetaFuse version and environment

### 4. Report Security Issues Privately

**NEVER post security vulnerabilities publicly.** Instead:

- Follow the [Security Policy](../.github/SECURITY.md)
- Email security concerns to the maintainers
- Allow time for responsible disclosure

---

## Community Guidelines

### Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](../CODE_OF_CONDUCT.md). By participating, you agree to:

- Be respectful and inclusive
- Welcome newcomers
- Give and receive constructive feedback gracefully
- Focus on what's best for the community
- Show empathy toward other community members

### Best Practices

**When asking questions:**

- Search first to avoid duplicates
- Provide enough context for others to help
- Follow up when you find a solution
- Mark answers that solved your problem

**When reporting bugs:**

- Use the bug report template
- Provide minimal reproduction steps
- Include version numbers and environment details
- Be patient while maintainers investigate

**When proposing features:**

- Explain the use case and motivation
- Consider backward compatibility
- Be open to feedback and alternative approaches
- Understand that not all features will be accepted

**When reviewing code:**

- Be constructive and specific
- Suggest improvements, don't just criticize
- Acknowledge good work
- Focus on the code, not the person

---

## Release Communication

### How to Stay Updated

1. **Watch the repository** on GitHub:
   - Click "Watch" → "Custom" → Enable "Releases"
   - Get notified about new releases

2. **Follow the CHANGELOG**:
   - [CHANGELOG.md](../CHANGELOG.md) documents all changes
   - Each release includes migration notes if needed

3. **Subscribe to Announcements**:
   - Watch the [Announcements category](https://github.com/ethan-tyler/MetaFuse/discussions/categories/announcements)
   - Important updates are posted there first

### Release Schedule

MetaFuse follows semantic versioning:

- **v0.x**: Experimental phase, APIs may change
- **v1.0+**: Stable releases with backward compatibility guarantees

See the [Roadmap](roadmap.md) for planned releases and features.

---

## Recognition and Credits

### Contributors

All contributors are recognized in:

- GitHub's contributor graph
- Release notes (for significant contributions)
- The community "Show and tell" category (for integrations and examples)

### How to Get Recognized

- Contribute code via pull requests
- Report bugs and help triage issues
- Answer questions in Discussions
- Write tutorials or blog posts
- Create examples and integrations
- Improve documentation

---

## Governance

### Decision-Making Process

MetaFuse follows a maintainer-led governance model:

1. **Minor changes** (bug fixes, docs, small features): Merged by any maintainer after review
2. **Major changes** (breaking changes, architecture): Require RFC and community discussion
3. **Roadmap priorities**: Influenced by community feedback and upvotes on issues

### Maintainers

Current maintainers are listed in [CODEOWNERS](../.github/CODEOWNERS) (if present).

**Maintainer responsibilities:**

- Review pull requests
- Triage issues
- Guide technical direction
- Ensure code quality and test coverage
- Communicate with the community

### Becoming a Maintainer

Active contributors may be invited to become maintainers based on:

- Consistent high-quality contributions
- Deep understanding of the codebase
- Constructive community participation
- Alignment with project values

---

## Events and Initiatives

### Community Calls (Future)

As the community grows, we may host:

- Monthly community calls
- Office hours with maintainers
- Demo sessions for new features

Stay tuned in the **Announcements** category for updates.

### Hacktoberfest

MetaFuse participates in Hacktoberfest! During October:

- Issues labeled `hacktoberfest` are beginner-friendly
- PRs count toward Hacktoberfest contributions
- Special recognition for Hacktoberfest participants

---

## Resources

### Learning Resources

- [Getting Started Guide](getting-started.md): First steps with MetaFuse
- [Examples](../examples/): Runnable code examples
- [API Reference](api-reference.md): Complete API documentation
- [Architecture Docs](for-developers.md): Deep dive into internals

### Integration Guides

- [Cloud Deployment Guides](deployment-aws.md): Deploy to AWS, GCP
- [Migration Guides](MIGRATION-v0.4.md): Upgrade between versions
- [Security Best Practices](SECURITY.md): Production security setup

### External Resources

- [DataFusion Documentation](https://arrow.apache.org/datafusion/): MetaFuse integrates with DataFusion
- [Apache Arrow](https://arrow.apache.org/): Schema format used by MetaFuse
- [SQLite FTS5](https://www.sqlite.org/fts5.html): Full-text search engine

---

## Contact

- **General questions**: [GitHub Discussions Q&A](https://github.com/ethan-tyler/MetaFuse/discussions)
- **Bug reports**: [GitHub Issues](https://github.com/ethan-tyler/MetaFuse/issues/new?template=bug_report.yml)
- **Security issues**: See [Security Policy](../.github/SECURITY.md)
- **Feature requests**: [GitHub Issues](https://github.com/ethan-tyler/MetaFuse/issues/new?template=feature_request.yml)

---

## Thank You!

Your participation makes MetaFuse better for everyone. Whether you're:

- Reporting bugs
- Answering questions
- Contributing code
- Writing documentation
- Sharing your projects

...you're helping build a better metadata catalog for the lakehouse ecosystem.

**Welcome to the MetaFuse community!**
