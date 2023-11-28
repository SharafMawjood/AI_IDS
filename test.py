import joblib
import sys
import numpy as np

# Load the trained classifier
loaded_classifier = joblib.load('grad_boost.pkl')

# Extract features from the software file (update this part as needed)
# extracted_features = features[0]
for feature in features:
    extracted_features = feature

    for i in range (len(extracted_features)):
        if extracted_features[i] == float('inf'):
            # assign maximum 32 bit float value
            extracted_features[i] = 999.99

    print(extracted_features)

    if extracted_features is not None:
        # Convert the extracted features to a numpy array with 'float64' data type
        extracted_features = np.array(extracted_features, dtype=np.float64)

        # Make a prediction using the loaded model
        prediction = loaded_classifier.predict([extracted_features])
        print(prediction)
        # Interpret the prediction
        # if prediction[0] == 1:
        #     print("The software is predicted to be legitimate.")
        # else:
        #     print("The software is predicted to be malicious.")
    else:
        # Feature extraction failed
        print("Feature extraction failed.")
