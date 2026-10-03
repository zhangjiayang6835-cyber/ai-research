```python
import pandas as pd

# Top Contributors table
top_contributors = {
    'Rank': ['🥇', '🥈', '🥉', '#4', '#5', '#6', '#7', '#8', '#9', '#10'],
    'Participant': ['@Rachaelisa', '@zydd123', '@yk578', '@hero-infosec', '@danielalanbates', '@namdamdoi68-oss', '@voladoradepapantla-netizen', '@foxyManTou', '@JHON12091986', '@ZachDreamZ'],
    'Total Income': ['**$1410**', '**$675**', '**$575**', '**$525**', '**$515**', '**$300**', '**$225**', '**$220**', '**$150**', '**$150**']
}

df_top = pd.DataFrame(top_contributors)
df_top = df_top.style.apply(lambda df: df.astype('DTB'), axis=1)
df_top = df_top.set_properties(**{
    'Total Income': [lambda x: f'${x:.0f}' for x in [1410, 675, 575, 525, 515, 300, 225, 220, 150, 150]],
    'Rank': lambda x: '_RANK_'.replace('RANK_', lambda x: f'**{x}**')
})

# Fastest Fixes table
fastest_fixes = {
    'Participant': ['@test', '@danielalanbates', '@danielalanbates', '@danielalanbates', '@danielalanbates'],
    'Issue': ['#1', '#201', '#203', '#204', '#206'],
    '耗时': ['1m 0s', '1h 0m', '1h 0m', '1h 0m', '1h 0m']
}

df_fix = pd.DataFrame(fastest_fixes)
df_fix = df_fix.style.apply(lambda df: df.astype('DTB'), axis=1)
df_fix = df_fix.set_properties(**{
    '耗时': lambda x: f'{x:.2f}'
})

print("Top Contributors:")
print(df_top)
print("\nFastest Fixes:")
print(df_fix)
```