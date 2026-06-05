---
layout: home
title: "Forensic Science Insights"
description: "Exploring the cutting edge of forensic technology and research"
---

# Welcome to Forensic Science Insights

Your premier source for cutting-edge forensic research, case studies, and technological advancements in criminal investigation.

## Latest Blog Posts

{% for post in site.posts limit:5 %}
- [{{ post.title }}]({{ post.url }}) - {{ post.date | date: "%B %d, %Y" }}
{% endfor %}

## Forensic Disciplines We Cover

- **Digital Forensics** - Computer and mobile device analysis
- **DNA Analysis** - Genetic evidence and profiling
- **Toxicology** - Drug and poison identification
- **Crime Scene Investigation** - Evidence collection and preservation
- **Forensic Pathology** - Cause and manner of death determination

[View All Posts](/posts.html) | [About This Blog](/about.html)
<!-- Site deployed successfully -->
