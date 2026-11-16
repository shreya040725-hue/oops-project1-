#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <algorithm>
#include <random>
#include <cctype>
#include <limits>

using namespace std;

// Base class
class Password {
private:
    string value;

public:
    explicit Password(const string& password) : value(password) {}

    string getValue() const {
        return value;
    }
};

// Abstract base class
class SecurityRule {
public:
    virtual bool check(const Password& password) const = 0;
    virtual string getName() const = 0;
    virtual ~SecurityRule() = default;
};

// Derived classes
class LengthRule : public SecurityRule {
public:
    bool check(const Password& p) const override {
        return p.getValue().length() >= 12;
    }

    string getName() const override {
        return "At least 12 characters";
    }
};

class UppercaseRule : public SecurityRule {
public:
    bool check(const Password& p) const override {
        for (unsigned char ch : p.getValue())
            if (isupper(ch)) return true;
        return false;
    }

    string getName() const override {
        return "Contains an uppercase letter";
    }
};

class LowercaseRule : public SecurityRule {
public:
    bool check(const Password& p) const override {
        for (unsigned char ch : p.getValue())
            if (islower(ch)) return true;
        return false;
    }

    string getName() const override {
        return "Contains a lowercase letter";
    }
};

class DigitRule : public SecurityRule {
public:
    bool check(const Password& p) const override {
        for (unsigned char ch : p.getValue())
            if (isdigit(ch)) return true;
        return false;
    }

    string getName() const override {
        return "Contains a number";
    }
};

class SpecialCharacterRule : public SecurityRule {
public:
    bool check(const Password& p) const override {
        for (unsigned char ch : p.getValue())
            if (!isalnum(ch) && !isspace(ch)) return true;
        return false;
    }

    string getName() const override {
        return "Contains a special character";
    }
};

class CommonPasswordRule : public SecurityRule {
public:
    bool check(const Password& p) const override {
        string text = p.getValue();

        transform(text.begin(), text.end(), text.begin(),
            [](unsigned char ch) {
                return static_cast<char>(tolower(ch));
            });

        vector<string> commonPasswords = {
            "password", "123456", "12345678", "qwerty",
            "admin", "letmein", "welcome", "iloveyou"
        };

        return find(commonPasswords.begin(),
                    commonPasswords.end(), text)
                    == commonPasswords.end();
    }

    string getName() const override {
        return "Avoids a commonly used password";
    }
};

// Password analyzer class
class PasswordAnalyzer {
private:
    vector<unique_ptr<SecurityRule>> rules;

public:
    PasswordAnalyzer() {
        rules.push_back(make_unique<LengthRule>());
        rules.push_back(make_unique<UppercaseRule>());
        rules.push_back(make_unique<LowercaseRule>());
        rules.push_back(make_unique<DigitRule>());
        rules.push_back(make_unique<SpecialCharacterRule>());
        rules.push_back(make_unique<CommonPasswordRule>());
    }

    void analyze(const Password& password) const {
        int score = 0;

        cout << "\n------ PASSWORD SECURITY REPORT ------\n";

        for (const auto& rule : rules) {
            bool passed = rule->check(password);

            cout << (passed ? "[PASS] " : "[FAIL] ")
                 << rule->getName() << '\n';

            if (passed)
                score++;
        }

        cout << "\nSecurity Score: " << score
             << "/" << rules.size() << '\n';

        string strength;

        if (score <= 2)
            strength = "Weak";
        else if (score <= 4)
            strength = "Moderate";
        else
            strength = "Strong";

        cout << "Password Strength: " << strength << '\n';
        cout << "--------------------------------------\n";
    }
};

// Password generator class
class PasswordGenerator {
public:
    string generate(int length) const {
        const string upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const string lower = "abcdefghijklmnopqrstuvwxyz";
        const string digits = "0123456789";
        const string special = "!@#$%^&*()-_=+";

        const string all = upper + lower + digits + special;

        random_device rd;
        mt19937 engine(rd());

        uniform_int_distribution<int> u(0, upper.size() - 1);
        uniform_int_distribution<int> l(0, lower.size() - 1);
        uniform_int_distribution<int> d(0, digits.size() - 1);
        uniform_int_distribution<int> s(0, special.size() - 1);
        uniform_int_distribution<int> a(0, all.size() - 1);

        string result;

        result += upper[u(engine)];
        result += lower[l(engine)];
        result += digits[d(engine)];
        result += special[s(engine)];

        while (result.length() < static_cast<size_t>(length))
            result += all[a(engine)];

        shuffle(result.begin(), result.end(), engine);

        return result;
    }
};

// Main function
int main() {
    PasswordAnalyzer analyzer;
    PasswordGenerator generator;

    int choice;

    do {
        cout << "\n======================================\n";
        cout << "       PASSWORD SECURITY SYSTEM\n";
        cout << "======================================\n";
        cout << "1. Analyze a password\n";
        cout << "2. Generate a secure password\n";
        cout << "3. Exit\n";
        cout << "Enter your choice: ";

        if (!(cin >> choice)) {
            cout << "Invalid input. Please enter a number.\n";
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            continue;
        }

        cin.ignore(numeric_limits<streamsize>::max(), '\n');

        if (choice == 1) {
            string input;

            cout << "Enter password to analyze: ";
            getline(cin, input);

            if (input.empty()) {
                cout << "Password cannot be empty.\n";
            } else {
                Password password(input);
                analyzer.analyze(password);
            }
        }

        else if (choice == 2) {
            int length;

            cout << "Enter password length (8-64): ";

            if (!(cin >> length)) {
                cout << "Invalid input. Please enter a whole number.\n";
                cin.clear();
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                continue;
            }

            cin.ignore(numeric_limits<streamsize>::max(), '\n');

            if (length < 8 || length > 64) {
                cout << "Please choose a length between 8 and 64.\n";
            } else {
                cout << "Generated Password: "
                     << generator.generate(length) << '\n';
            }
        }

        else if (choice == 3) {
            cout << "Thank you for using Password Security System!\n";
        }

        else {
            cout << "Invalid choice. Please select 1, 2, or 3.\n";
        }

    } while (choice != 3);

    return 0;
}
