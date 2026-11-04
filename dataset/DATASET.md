# Synthetic security activity sample

This CSV is **synthetic**. It is used to train Isolation Forest on a repeatable
baseline of office-hour, low-failure, stable-IP behaviour and to evaluate the
pipeline in tests.

It does **not** represent real cloud tenant traffic and must not be cited as
real-world detection accuracy.

Columns are the numeric features defined in `ai_engine/preprocess.py` plus
`label` (`normal` or `anomalous`) for analysis only. Isolation Forest training
uses `normal` rows unsupervised; labels are not fed into Isolation Forest.
