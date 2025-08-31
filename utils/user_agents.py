import random
import requests
from typing import Dict, List, Optional

class UserAgentManager:
    """
    User Agent Manager for handling user agent rotation and customization.
    Provides methods to get random user agents, specific browser agents, and manage user agent lists.
    """
    
    def __init__(self):
        self.user_agents = {
            'chrome': [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            ],
            'firefox': [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0',
                'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0'
            ],
            'safari': [
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
                'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1'
            ],
            'edge': [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0'
            ],
            'mobile': [
                'Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
                'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1'
            ]
        }
        
        # Custom user agents that can be added/removed
        self.custom_agents = []
    
    def get_random_agent(self, browser: Optional[str] = None) -> str:
        """
        Get a random user agent string.
        
        Args:
            browser (str, optional): Specific browser type ('chrome', 'firefox', 'safari', 'edge', 'mobile')
                                   If None, returns random from all categories.
        
        Returns:
            str: Random user agent string
        """
        if browser and browser.lower() in self.user_agents:
            return random.choice(self.user_agents[browser.lower()])
        
        # Combine all agents and custom ones
        all_agents = []
        for agents in self.user_agents.values():
            all_agents.extend(agents)
        all_agents.extend(self.custom_agents)
        
        return random.choice(all_agents) if all_agents else 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    
    def get_chrome_agent(self) -> str:
        """Get a random Chrome user agent."""
        return self.get_random_agent('chrome')
    
    def get_firefox_agent(self) -> str:
        """Get a random Firefox user agent."""
        return self.get_random_agent('firefox')
    
    def get_safari_agent(self) -> str:
        """Get a random Safari user agent."""
        return self.get_random_agent('safari')
    
    def get_mobile_agent(self) -> str:
        """Get a random mobile user agent."""
        return self.get_random_agent('mobile')
    
    def set_user_agent(self, session: requests.Session, browser: Optional[str] = None) -> requests.Session:
        """
        Set a random user agent in the session headers.
        
        Args:
            session (requests.Session): The requests session to modify
            browser (str, optional): Specific browser type for user agent
        
        Returns:
            requests.Session: The modified session with updated headers
        """
        user_agent = self.get_random_agent(browser)
        session.headers.update({'User-Agent': user_agent})
        return session
    
    def add_custom_agent(self, agent_string: str) -> None:
        """
        Add a custom user agent to the list.
        
        Args:
            agent_string (str): The custom user agent string to add
        """
        if agent_string and agent_string not in self.custom_agents:
            self.custom_agents.append(agent_string)
    
    def remove_custom_agent(self, agent_string: str) -> bool:
        """
        Remove a custom user agent from the list.
        
        Args:
            agent_string (str): The custom user agent string to remove
        
        Returns:
            bool: True if removed, False if not found
        """
        if agent_string in self.custom_agents:
            self.custom_agents.remove(agent_string)
            return True
        return False
    
    def list_agents(self, browser: Optional[str] = None) -> List[str]:
        """
        List all available user agents.
        
        Args:
            browser (str, optional): Specific browser type to list
        
        Returns:
            List[str]: List of user agent strings
        """
        if browser and browser.lower() in self.user_agents:
            return self.user_agents[browser.lower()].copy()
        
        all_agents = []
        for agents in self.user_agents.values():
            all_agents.extend(agents)
        all_agents.extend(self.custom_agents)
        return all_agents
    
    def get_agent_count(self, browser: Optional[str] = None) -> int:
        """
        Get the count of available user agents.
        
        Args:
            browser (str, optional): Specific browser type to count
        
        Returns:
            int: Number of user agents available
        """
        if browser and browser.lower() in self.user_agents:
            return len(self.user_agents[browser.lower()])
        
        total = sum(len(agents) for agents in self.user_agents.values())
        total += len(self.custom_agents)
        return total