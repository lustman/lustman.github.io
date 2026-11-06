---
layout: default
title: Home
---

## Posts

{% for note in site.notes %}
<div class="groupbox">
  <h2><a href="{{ note.url }}">{{ note.title }}</a></h2>
</div>
{% endfor %}