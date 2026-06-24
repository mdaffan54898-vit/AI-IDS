import pandas as pd
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib

# Load dataset
data = pd.read_csv("datasets/UNSW/UNSW_NB15.csv")

# Drop ID column
if 'id' in data.columns:
    data = data.drop('id', axis=1)

# Features and target
X = data.drop(['label', 'attack_cat'], axis=1)
y = data['attack_cat'].fillna('Normal')  # Fill NaN with 'Normal' for normal traffic

# Print class distribution
print("\n--- Data for Class Distribution Chart (Pie or Bar Chart) ---")
print("Copy the following CSV data into Excel:")
print(y.value_counts().to_csv())
print("-" * 60)


# Encode target with LabelEncoder
from sklearn.preprocessing import LabelEncoder
le = LabelEncoder()
y_encoded = le.fit_transform(y)

# One-hot encode categorical features
cat_cols = ['proto', 'service', 'state']
X = pd.get_dummies(X, columns=cat_cols)

# Save feature column order so inference can reindex correctly
feature_columns = list(X.columns)
joblib.dump(feature_columns, 'feature_columns.pkl')

# Scale features (important to match at inference time)
scaler = MinMaxScaler()
X = scaler.fit_transform(X)

# Split dataset (X is already scaled)
X_train, X_test, y_train, y_test = train_test_split(X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded)

# XGBoost classifier for multi-class
model = xgb.XGBClassifier(
    objective='multi:softmax',  # multi-class
    num_class=len(le.classes_),  # number of attack types + normal
    n_estimators=200,      # Keep as before
    max_depth=6,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    tree_method='hist',
    eval_metric='mlogloss',
    use_label_encoder=False,
    random_state=42,
    n_jobs=-1
)

# Train the model
model.fit(X_train, y_train)

# Predict & evaluate
y_pred = model.predict(X_test)
print("Accuracy:", accuracy_score(y_test, y_pred))
print("Classification Report:\n", classification_report(y_test, y_pred, target_names=le.classes_))

# --- Additional Data for Charts ---

# 1. Confusion Matrix
print("\n--- Data for Confusion Matrix (Heatmap) ---")
print("Copy the following CSV data into Excel. Use Conditional Formatting -> Color Scales to create a heatmap.")
cm = confusion_matrix(y_test, y_pred)
cm_df = pd.DataFrame(cm, index=le.classes_, columns=le.classes_)
print(cm_df.to_csv())
print("-" * 60)

# 2. Feature Importance
print("\n--- Data for Feature Importance Chart (Horizontal Bar Chart) ---")
print("Copy the following CSV data into Excel to create a horizontal bar chart.")
feature_importances = pd.DataFrame({'feature': feature_columns, 'importance': model.feature_importances_})
feature_importances = feature_importances.sort_values('importance', ascending=False).head(20)
print(feature_importances.to_csv(index=False))
print("-" * 60)


# Saving the trained model and encoder
joblib.dump(model, 'xgboost_model_multi.pkl')
joblib.dump(le, 'label_encoder.pkl')
joblib.dump(scaler, 'scaler.pkl')
print("Model, encoder, scaler and feature columns saved successfully!")