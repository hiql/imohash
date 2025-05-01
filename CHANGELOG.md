# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

- [x] feature: make module constants public to allow their usage in user code
- [x] feature: generalize `path_file` argument type, from `&str` to `AsRef<Path>`
- [x] feature: allow only regular file for hashing with `sum_file`
- [x] enhancement: add additional entropy to filename to fix race condition issue on parallel tests launch
- [x] feature: implement CLI application
- [x] documentation: add basic and advanced usage examples