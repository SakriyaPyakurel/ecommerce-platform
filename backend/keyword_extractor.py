from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.feature_extraction.text import TfidfVectorizer
class KeywordExtractor(BaseEstimator, TransformerMixin):
    def __init__(self, top_n=5):
        self.top_n = top_n

    def fit(self, X, y=None):
        self.vectorizer = TfidfVectorizer(stop_words='english')
        self.vectorizer.fit(X)
        return self

    def transform(self, X):
        tfidf_matrix = self.vectorizer.transform(X)
        feature_names = self.vectorizer.get_feature_names_out()
        
        keywords_list = []
        for row in tfidf_matrix:
            row = row.toarray().flatten()
            top_indices = row.argsort()[-self.top_n:][::-1]
            keywords = " ".join([feature_names[i] for i in top_indices])
            keywords_list.append(keywords)
        
        return keywords_list