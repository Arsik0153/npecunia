from transformers import pipeline

text = """ 
Mini XRP is a hyper deflationary token designed to reward holders over time. All holders of MXRP will earn 5% in reflection rewards, that will go straight...
"""


summarizer = pipeline("summarization")
summarized = summarizer(text, min_length=10, max_length=30)

# Print summarized text
print(summarized)
