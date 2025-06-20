# Abstract Base Class

from abc import ABC, abstractmethod

class BaseAnalyzer(ABC):
    def __init__(self, content):
        self.content = content  #Stores data from the user to be analyzed
        self.findings = []  #list is empty to keep track of errors/warnings found
        self.raw_scores = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}  #Holds points for 3 risk levels

    @abstractmethod    #Each analyzer derived from this class must write its own analyze() function
    def analyze(self):   
        pass   

    def get_score(self):
        weight = {"HIGH": 4, "MEDIUM": 2, "LOW": 1}
        raw = self.raw_scores
        total_points = (raw["HIGH"] * weight["HIGH"] +    #raw = how much weight risk type equals that much points and then we must add them to eachother
                        raw["MEDIUM"] * weight["MEDIUM"] +
                        raw["LOW"] * weight["LOW"])
        return round(min(total_points / 24 * 10, 10))   #based of max 10 points  #round: rounding up the result #In my point system you can get a maximum of 24 points otherwise this file is already a very vulnerable

    def get_score_breakdown(self):
        return self.raw_scores   #to show user how many bugs are found at which level in gui

    @property   #if there was not this code we should is it with object "()"
    def issue_count(self):
        return sum(self.raw_scores.values())   #sum of the total error number only
