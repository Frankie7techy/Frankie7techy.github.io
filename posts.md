---
layout: page
title: "All Blog Posts"
permalink: /posts/
---

# All Forensic Science Posts

{% for post in site.posts %}
## [{{ post.title }}]({{ post.url }})
*Published: {{ post.date | date: "%B %d, %Y" }}*
{% if post.categories %}
*Categories: {{ post.categories | join: ", " }}*
{% endif %}

{{ post.excerpt | strip_html | truncatewords: 30 }}

---
{% endfor %}
